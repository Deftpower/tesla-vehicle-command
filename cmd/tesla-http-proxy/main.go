package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/teslamotors/vehicle-command/internal/log"
	"github.com/teslamotors/vehicle-command/pkg/cli"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	"github.com/teslamotors/vehicle-command/pkg/proxy"
)

const (
	cacheSize = 10000 // Number of cached vehicle sessions
	defaultPort = 8080
	defaultPortHTTPS = 8443
)

const (
	EnvTLSCert = "TESLA_HTTP_PROXY_TLS_CERT"
	EnvTLSKey  = "TESLA_HTTP_PROXY_TLS_KEY"
	EnvHost    = "TESLA_HTTP_PROXY_HOST"
	EnvPort    = "TESLA_HTTP_PROXY_PORT"
	EnvTimeout = "TESLA_HTTP_PROXY_TIMEOUT"
	EnvVerbose = "TESLA_VERBOSE"
	EnvDisableTLS = "TESLA_HTTP_PROXY_DISABLE_TLS"
)

const nonLocalhostWarning = `
Do not listen on a network interface without adding client authentication. Unauthorized clients may
be used to create excessive traffic from your IP address to Tesla's servers, which Tesla may respond
to by rate limiting or blocking your connections.`

type HTTProxyConfig struct {
	keyFilename  string
	certFilename string
	verbose      bool
	host         string
	port         int
	timeout      time.Duration
}

var (
	httpConfig = &HTTProxyConfig{}
)

func init() {
	flag.StringVar(&httpConfig.certFilename, "cert", "", "TLS certificate chain `file` with concatenated server, intermediate CA, and root CA certificates")
	flag.StringVar(&httpConfig.keyFilename, "tls-key", "", "Server TLS private key `file`")
	flag.BoolVar(&httpConfig.verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&httpConfig.host, "host", "localhost", "Proxy server `hostname`")
	flag.IntVar(&httpConfig.port, "port", defaultPort, "`Port` to listen on")
	flag.DurationVar(&httpConfig.timeout, "timeout", proxy.DefaultTimeout, "Timeout interval when sending commands")
}

func Usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage: %s [OPTION...]\n", os.Args[0])
	fmt.Fprintf(out, "\nA server that exposes a REST API for sending commands to Tesla vehicles")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, nonLocalhostWarning)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Options:")
	flag.PrintDefaults()
}

func main() {
	// ******************************************************************************************
	// WHY IS THERE NO OPTION FOR DISABLING TLS?
	// ******************************************************************************************
	// In the past, we have had problems with third-party applications that made it easy for DIY
	// enthusiasts to inadvertently expose their vehicles to the public Internet. In order to
	// protect users who do not understand the risks of disabling TLS, we decided to omit an
	// --insecure flag or similar.
	//
	// Expert users who need to disable TLS can do so without forking this repository by using the
	// pkg/proxy package, which is agnostic to TLS. This application is a very thin wrapper around
	// that package.

	config, err := cli.NewConfig(cli.FlagPrivateKey)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load credential configuration: %s\n", err)
		os.Exit(1)
	}

	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	}()

	flag.Usage = Usage
	config.RegisterCommandLineFlags()
	flag.Parse()
	err = readFromEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading environment: %s\n", err)
		os.Exit(1)
	}
	config.ReadFromEnvironment()

	if httpConfig.verbose {
		log.SetLevel(log.LevelDebug)
	}

	if httpConfig.host != "localhost" {
		fmt.Fprintln(os.Stderr, nonLocalhostWarning)
	}

	var skey protocol.ECDHPrivateKey
	skey, err = config.PrivateKey()
	if err != nil {
		return
	}

	// Check if TLS is disabled early
	var useTLS bool = true
	if disableTLS, ok := os.LookupEnv(EnvDisableTLS); ok {
		useTLS = disableTLS != "true"
	}

	// Only validate TLS key if TLS is enabled
	if useTLS {
		if tlsPublicKey, err := protocol.LoadPublicKey(httpConfig.keyFilename); err == nil {
			if bytes.Equal(tlsPublicKey.Bytes(), skey.PublicBytes()) {
				fmt.Fprintln(os.Stderr, "It is unsafe to use the same private key for TLS and command authentication.")
				fmt.Fprintln(os.Stderr, "")
				fmt.Fprintln(os.Stderr, "Generate a new TLS key for this server.")
				return
			}
			log.Debug("Verified that TLS key is not the same as the command-authentication key.")
		} else {
			// Discarding the error here is deliberate
			log.Debug("Verified that TLS key is not a recycled command-authentication key, because it is not NIST P256.")
		}
	}

	log.Debug("Creating proxy")
	p, err := proxy.New(context.Background(), skey, cacheSize)
	if err != nil {
		log.Error("Error initializing proxy service: %v", err)
		return
	}
	p.Timeout = httpConfig.timeout
	addr := fmt.Sprintf("%s:%d", httpConfig.host, httpConfig.port)
	log.Info("Listening on %s", addr)

	if useTLS && httpConfig.certFilename != "" && httpConfig.keyFilename != "" {
		log.Error("Server stopped: %s", http.ListenAndServeTLS(addr, httpConfig.certFilename, httpConfig.keyFilename, p))
	} else {
		log.Error("Server stopped: %s", http.ListenAndServe(addr, p))
	}
}

// readConfig applies configuration from environment variables.
// Values are not overwritten.
func readFromEnvironment() error {
	if httpConfig.certFilename == "" {
		httpConfig.certFilename = os.Getenv(EnvTLSCert)
	}

	if httpConfig.keyFilename == "" {
		httpConfig.keyFilename = os.Getenv(EnvTLSKey)
	}

	if httpConfig.host == "localhost" {
		host, ok := os.LookupEnv(EnvHost)
		if ok {
			httpConfig.host = host
		}
	}

	if !httpConfig.verbose {
		if verbose, ok := os.LookupEnv(EnvVerbose); ok {
			httpConfig.verbose = verbose != "false" && verbose != "0"
		}
	}

	var err error
	if httpConfig.port == defaultPort {
		if port, ok := os.LookupEnv(EnvPort); ok {
			httpConfig.port, err = strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("invalid port: %s", port)
			}
		}
	}

	if httpConfig.timeout == proxy.DefaultTimeout {
		if timeoutEnv, ok := os.LookupEnv(EnvTimeout); ok {
			httpConfig.timeout, err = time.ParseDuration(timeoutEnv)
			if err != nil {
				return fmt.Errorf("invalid timeout: %s", timeoutEnv)
			}
		}
	}

	return nil
}
