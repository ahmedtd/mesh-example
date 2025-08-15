package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/subcommands"
)

type HTTPSClientCommand struct {
	fetchURL string

	serverTrustBundleFile string

	clientCredBundleFile string
}

var _ subcommands.Command = (*HTTPSClientCommand)(nil)

func (*HTTPSClientCommand) Name() string {
	return "https-client"
}

func (*HTTPSClientCommand) Synopsis() string {
	return "Run a vanilla HTTPS client"
}

func (*HTTPSClientCommand) Usage() string {
	return ``
}

func (c *HTTPSClientCommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.fetchURL, "fetch-url", "", "URL to poll")
	f.StringVar(&c.serverTrustBundleFile, "server-trust-bundle", "", "File with trust anchors to verify the server certificate")

	f.StringVar(
		&c.clientCredBundleFile,
		"client-cred-bundle",
		"",
		"File with client key and certificate chain",
	)
}

func (c *HTTPSClientCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	for range time.Tick(10 * time.Second) {
		if err := c.pollOnce(ctx); err != nil {
			log.Printf("Error: %v", err)
		}
	}

	return subcommands.ExitSuccess
}

func (c *HTTPSClientCommand) pollOnce(ctx context.Context) error {
	trustBundlePEM, err := os.ReadFile(c.serverTrustBundleFile)
	if err != nil {
		return fmt.Errorf("while reading service trust bundle: %w", err)
	}

	serverTrustAnchors := x509.NewCertPool()
	serverTrustAnchors.AppendCertsFromPEM(trustBundlePEM)

	tlsConfig := &tls.Config{
		RootCAs: serverTrustAnchors,
	}

	// Load and send client certificates if a bundle file was specified.
	if c.clientCredBundleFile != "" {
		bundlePEM, err := os.ReadFile(c.clientCredBundleFile)
		if err != nil {
			return fmt.Errorf("while reading client credential bundle: %w", err)
		}

		cert := tls.Certificate{}

		var block *pem.Block
		rest := bundlePEM
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}

			switch block.Type {
			case "PRIVATE KEY":
				cert.PrivateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return fmt.Errorf("while parsing private key from credential bundle: %w", err)
				}
			case "CERTIFICATE":
				cert.Certificate = append(cert.Certificate, block.Bytes)
			}
		}

		if cert.PrivateKey == nil {
			return fmt.Errorf("client credential bundle had no private key")
		}

		if len(cert.Certificate) == 0 {
			return fmt.Errorf("client credential bundle had no certificates")
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// TODO: Support the server presenting pod identity or spiffe certificates.

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	resp, err := client.Get(c.fetchURL)
	if err != nil {
		return fmt.Errorf("while getting URL: %w", err)

	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx status %d %q", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return fmt.Errorf("while reading body: %w", err)
	}

	log.Printf("Got body: %s", string(body))
	return nil
}
