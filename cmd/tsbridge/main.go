// Package main provides the tsbridge CLI application for managing Tailscale proxy services.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jtdowney/tsbridge/internal/app"
	"github.com/jtdowney/tsbridge/internal/config"
	"github.com/jtdowney/tsbridge/internal/constants"
	"log/slog"
)

var version = "dev"

// exitFunc allows tests to override os.Exit
var exitFunc = os.Exit

func main() {
	var (
		configPath  = flag.String("config", "", "Path to TOML configuration file (required)")
		verbose     = flag.Bool("verbose", false, "Enable debug logging")
		help        = flag.Bool("help", false, "Show usage information")
		versionFlag = flag.Bool("version", false, "Show version information")
	)

	// Override flag.Usage to output to stdout instead of stderr
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *help {
		flag.Usage()
		exitFunc(0)
	}

	if *versionFlag {
		fmt.Printf("tsbridge version: %s\n", version)
		exitFunc(0)
	}

	// Configure logging
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if *verbose {
		opts.Level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	if *configPath == "" {
		slog.Error("-config flag is required")
		exitFunc(1)
	}

	slog.Debug("starting tsbridge", "version", version)

	// Load configuration
	slog.Debug("loading config", "path", *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		exitFunc(1)
	}

	if *verbose {
		// Print parsed config for debugging (with secrets redacted)
		slog.Debug("parsed config", "config", cfg.String())
	}

	// Create the application
	slog.Debug("creating application")
	application, err := app.NewApp(cfg)
	if err != nil {
		slog.Error("failed to create application", "error", err)
		exitFunc(1)
	}

	// Start the application
	ctx := context.Background()
	if err := application.Start(ctx); err != nil {
		slog.Error("failed to start application", "error", err)
		exitFunc(1)
	}

	// Setup signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Single goroutine for signal listening
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)

		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), constants.DefaultShutdownTimeout)
		defer cancel()

		// Call shutdown
		if err := application.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "error", err)
			exitFunc(1)
		}

		exitFunc(0)
	}()

	// Block forever (until signal handler exits)
	select {}
}
