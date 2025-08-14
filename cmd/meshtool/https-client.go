package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	fetchURL    string
	trustBundle string
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
	f.StringVar(&c.trustBundle, "trust-bundle", "", "File with trust anchors to verify the server certificate")
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
	trustBundlePEM, err := os.ReadFile(c.trustBundle)
	if err != nil {
		return fmt.Errorf("while reading service trust bundle: %w", err)
	}

	serverTrustAnchors := x509.NewCertPool()
	serverTrustAnchors.AppendCertsFromPEM(trustBundlePEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: serverTrustAnchors,
			},
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
