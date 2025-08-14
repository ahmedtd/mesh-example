package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/subcommands"
)

type VanillaHTTPSServerCommand struct {
	listen          string
	serverCredsFile string
}

var _ subcommands.Command = (*VanillaHTTPSServerCommand)(nil)

func (*VanillaHTTPSServerCommand) Name() string {
	return "vanilla-https-server"
}

func (*VanillaHTTPSServerCommand) Synopsis() string {
	return "Run a vanilla HTTPS server"
}

func (*VanillaHTTPSServerCommand) Usage() string {
	return ``
}

func (c *VanillaHTTPSServerCommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.listen, "listen", "", "<address>:<port> to listen on")
	f.StringVar(&c.serverCredsFile, "server-creds", "", "Credential bundle with the server key and certificate chain")
}

func (c *VanillaHTTPSServerCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *VanillaHTTPSServerCommand) do(ctx context.Context) error {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("GET /healthz", c.handleGetHealthz)

	server := &http.Server{
		Addr: c.listen,

		Handler: serveMux,

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

func (c *VanillaHTTPSServerCommand) handleGetHealthz(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("Error while writing response: %v", err)
		return
	}
}
