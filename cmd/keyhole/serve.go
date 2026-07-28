package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/httpapi"
	"github.com/ssan9876/keyhole/internal/secret"
	"github.com/ssan9876/keyhole/internal/store"
	"github.com/ssan9876/keyhole/internal/webui"
)

func parseLevel(name string) slog.Level {
	switch strings.ToLower(name) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// isLoopbackAddr reports whether addr (a host:port pair, as stored in
// Config.Addr) only accepts connections from this machine. An empty host
// (":8477") binds every interface and is not loopback; a bare hostname other
// than "localhost" is treated as routable too, since the safer assumption
// when we cannot prove otherwise is to warn.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.yml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serve(cfg, shutdownCtx, nil)
}

// serve builds and runs the server described by cfg until shutdownCtx is
// cancelled or the server itself fails. It blocks either way, returning nil
// on a clean shutdown.
//
// If ready is non-nil, serve sends it the address the listener actually
// bound before serving a single request. That is the seam a test needs:
// cfg.Addr can end in ":0" (let the kernel pick a free port), and without
// this signal a test could only guess at the resulting port or poll for it.
func serve(cfg config.Config, shutdownCtx context.Context, ready chan<- string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))

	serverSecret, err := secret.LoadOrCreate(cfg.SecretPath())
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	// Migrating on start means an operator who forgets `keyhole migrate` after
	// an upgrade still gets a working server rather than confusing errors.
	if err := st.Migrate(context.Background()); err != nil {
		return err
	}

	webHandler, err := webui.Handler()
	if err != nil {
		return err
	}
	if !webui.Built() {
		logger.Warn("web app not built; serving the placeholder page for every route")
	}

	api := httpapi.New(cfg, st, serverSecret, logger, httpapi.WithWebUI(webHandler))
	defer api.Close()

	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Addr, err)
	}

	// Not fatal: a reverse proxy in front of a loopback bind is a correct
	// deployment, and so is a tunnel. Binding a routable address in the clear
	// is not, and the operator should hear about it at the moment they do it
	// rather than from a user who cannot unlock.
	if !cfg.TLSEnabled() && !isLoopbackAddr(cfg.Addr) {
		logger.Warn("serving without TLS on a non-loopback address; " +
			"the web app needs a secure context and will not be able to decrypt anything")
	}

	if ready != nil {
		ready <- listener.Addr().String()
	}

	errCh := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLSEnabled() {
			logger.Info("listening", "addr", listener.Addr().String(), "tls", true, "base_url", cfg.BaseURL)
			err = srv.ServeTLS(listener, cfg.TLSCert, cfg.TLSKey)
		} else {
			logger.Info("listening", "addr", listener.Addr().String(), "tls", false, "base_url", cfg.BaseURL)
			err = srv.Serve(listener)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-shutdownCtx.Done():
		logger.Info("shutting down")
		graceCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(graceCtx)
	}
}
