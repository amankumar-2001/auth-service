// Command http-server is the auth-service entry point. It loads configuration,
// builds the dependency graph, starts the HTTP server, and shuts down gracefully
// on SIGINT/SIGTERM.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/kharchibook/auth-service/config"
	"github.com/kharchibook/auth-service/pkg/application/httpserver"
	"github.com/kharchibook/auth-service/pkg/di"
	"github.com/kharchibook/auth-service/third_party/platlogger"
)

func main() {
	if err := run(); err != nil {
		platlogger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logLevel := "info"
	if cfg.App.Env == "dev" {
		logLevel = "debug"
	}
	platlogger.Init(cfg.App.Name, logLevel)
	platlogger.Info("starting auth-service", "env", cfg.App.Env)

	app, err := di.InitializeApp(cfg)
	if err != nil {
		return fmt.Errorf("initialize app: %w", err)
	}
	defer func() { _ = app.Close() }()

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      httpserver.NewRouter(app),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start the server; errors (other than the expected ErrServerClosed) abort.
	serverErr := make(chan error, 1)
	go func() {
		platlogger.Info("http server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// Wait for a shutdown signal or a fatal server error.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return fmt.Errorf("http server: %w", err)
	case sig := <-stop:
		platlogger.Info("shutdown signal received", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	platlogger.Info("server stopped cleanly")
	return nil
}
