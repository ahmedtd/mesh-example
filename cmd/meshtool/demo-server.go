package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/ahmedtd/mesh-example/lib/spiffesigner"
	"github.com/google/subcommands"
	"k8s.io/klog/v2"
)

type DemoServerCommand struct {
	listen          string
	serverCredsFile string

	enableSPIFFEClientSupport bool
	spiffeTrustBundleFile     string
}

var _ subcommands.Command = (*DemoServerCommand)(nil)

func (*DemoServerCommand) Name() string {
	return "demo-server"
}

func (*DemoServerCommand) Synopsis() string {
	return "Run an HTTP server that supports standard and mutual TLS"
}

func (*DemoServerCommand) Usage() string {
	return ``
}

func (c *DemoServerCommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.listen, "listen", "", "<address>:<port> to listen on")
	f.StringVar(&c.serverCredsFile, "server-creds", "", "Credential bundle with the server key and certificate chain")

	f.BoolVar(
		&c.enableSPIFFEClientSupport,
		"enable-spiffe-client-support",
		false,
		fmt.Sprintf("Support client certificates issued by %s", spiffesigner.Name),
	)
	f.StringVar(
		&c.spiffeTrustBundleFile,
		"spiffe-trust-bundle",
		"",
		fmt.Sprintf("Trust bundle for verifying certificates issued by %s", spiffesigner.Name),
	)
}

func (c *DemoServerCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		slog.ErrorContext(ctx, "Error: ", slog.String("err", err.Error()))
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *DemoServerCommand) do(ctx context.Context) error {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("GET /healthz", c.handleGetHealthz)
	serveMux.HandleFunc("GET /spiffe-echo", c.handleGetSPIFFEEcho)

	server := &http.Server{
		Addr: c.listen,

		Handler: serveMux,

		TLSConfig: &tls.Config{
			// Tell the client to send client certs if they have any.  Don't
			// pass in roots to verify the client certificate, since we expect
			// multiple types signed by different CAs.  Instead, each endpoint
			// will do the appropriate client certificate verification.
			ClientAuth: tls.RequestClientCert,
		},

		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// TODO: Auto-reload the server creds
	if err := server.ListenAndServeTLS(c.serverCredsFile, c.serverCredsFile); err != nil {
		return fmt.Errorf("while listening: %w", err)
	}

	return nil
}

func (c *DemoServerCommand) handleGetHealthz(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("Error while writing response: %v", err)
		return
	}
}

func (c *DemoServerCommand) handleGetSPIFFEEcho(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "SPIFFE client certificate authentication required", http.StatusUnauthorized)
		return
	}

	leafCert := r.TLS.PeerCertificates[0]

	// TODO: Use the trust domain from the leaf certificate to select which
	// trust bundle to use, to permit federated use cases.

	intermediatePool := x509.NewCertPool()
	if len(r.TLS.PeerCertificates) > 1 {
		for _, intermediate := range r.TLS.PeerCertificates[1:] {
			intermediatePool.AddCert(intermediate)
		}
	}

	rootTrustBundlePEM, err := os.ReadFile(c.spiffeTrustBundleFile)
	if err != nil {
		klog.ErrorS(err, "Error while reading SPIFFE trust anchors")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(rootTrustBundlePEM)

	chains, err := leafCert.Verify(x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         rootPool,
	})
	if err != nil {
		klog.ErrorS(err, "Error while verifying SPIFFE client certificate")
		http.Error(w, "SPIFFE client certificate authentication required", http.StatusUnauthorized)
		return
	}
	if len(chains) == 0 {
		klog.ErrorS(nil, "Client certificate did not chain to any roots")
		http.Error(w, "SPIFFE client certificate authentication required", http.StatusUnauthorized)
		return
	}

	if len(leafCert.URIs) != 1 {
		klog.ErrorS(nil, "SPIFFE client certificate did not have 1 URI SAN", "count", len(leafCert.URIs))
		http.Error(w, "Malformed SPIFFE certificate", http.StatusUnauthorized)
		return
	}

	if _, err := w.Write([]byte("Client Identity: " + leafCert.URIs[0].String())); err != nil {
		klog.ErrorS(err, "Error while writing response")
	}
}
