// Package app provides the main application lifecycle management for tsbridge.
package app

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/jtdowney/tsbridge/internal/config"
	tserrors "github.com/jtdowney/tsbridge/internal/errors"
	"github.com/jtdowney/tsbridge/internal/metrics"
	"github.com/jtdowney/tsbridge/internal/service"
	"github.com/jtdowney/tsbridge/internal/tailscale"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// App encapsulates the tsbridge application lifecycle
type App struct {
	cfg           *config.Config
	tsServer      *tailscale.Server
	registry      *service.Registry
	metricsServer *metrics.Server
	startOnce     sync.Once
	stopOnce      sync.Once
}

// Options allows customizing App creation for testing
type Options struct {
	TSServer *tailscale.Server
	Registry *service.Registry
}

// NewApp creates a new App instance with the given configuration
func NewApp(cfg *config.Config) (*App, error) {
	return NewAppWithOptions(cfg, Options{})
}

// NewAppWithOptions creates a new App instance with custom options
func NewAppWithOptions(cfg *config.Config, opts Options) (*App, error) {
	if cfg == nil {
		return nil, tserrors.NewValidationError("config cannot be nil")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		// The error from Validate is already a validation error
		return nil, err
	}

	var tsServer *tailscale.Server
	var registry *service.Registry
	var err error

	// Use provided tsServer or create new one
	if opts.TSServer != nil {
		tsServer = opts.TSServer
	} else {
		// Create tailscale server
		slog.Debug("creating tailscale server")
		tsServer, err = tailscale.NewServer(cfg.Tailscale)
		if err != nil {
			return nil, tserrors.WrapResource(err, "failed to create tailscale server")
		}
	}

	// Use provided registry or create new one
	if opts.Registry != nil {
		registry = opts.Registry
	} else {
		// Create service registry
		registry = service.NewRegistry(cfg, tsServer)
	}

	app := &App{
		cfg:      cfg,
		tsServer: tsServer,
		registry: registry,
	}

	// Setup metrics if configured
	if cfg.Global.MetricsAddr != "" {
		if err := app.setupMetrics(); err != nil {
			// Clean up tsServer if metrics setup fails and we created it
			if opts.TSServer == nil {
				tsServer.Close()
			}
			return nil, tserrors.WrapResource(err, "failed to setup metrics")
		}
	}

	return app, nil
}

// setupMetrics initializes the metrics server and collector
func (a *App) setupMetrics() error {
	slog.Debug("creating metrics collector")
	collector := metrics.NewCollector()
	reg := prometheus.NewRegistry()

	// Register default collectors (Go runtime and process metrics)
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	if err := collector.Register(reg); err != nil {
		return tserrors.WrapResource(err, "failed to register metrics")
	}

	// Set metrics collector on registry
	a.registry.SetMetricsCollector(collector)

	// Create metrics server (but don't start it yet)
	a.metricsServer = metrics.NewServerWithRegistry(a.cfg.Global.MetricsAddr, reg, a.cfg.Global.MetricsReadHeaderTimeout.Duration)

	return nil
}

// Start starts the application and all its services
func (a *App) Start(ctx context.Context) error {
	var startErr error
	a.startOnce.Do(func() {
		// Start metrics server if configured
		if a.metricsServer != nil {
			slog.Debug("starting metrics server", "address", a.cfg.Global.MetricsAddr)
			if err := a.metricsServer.Start(ctx); err != nil {
				startErr = tserrors.WrapResource(err, "failed to start metrics server")
				return
			}
			slog.Info("metrics server listening", "address", a.metricsServer.Addr())
		}

		// Start services
		slog.Info("starting services")
		if err := a.registry.StartServices(); err != nil {
			// Check if this is a partial failure
			if startupErr, ok := tserrors.AsServiceStartupError(err); ok && !startupErr.AllFailed() {
				// Some services started successfully, log the failures but continue
				slog.Warn("some services failed to start",
					"successful", startupErr.Successful,
					"failed", startupErr.Failed,
					"total", startupErr.Total)
				for service, serviceErr := range startupErr.Failures {
					slog.Error("service startup failed",
						"service", service,
						"error", serviceErr)
				}
				// Continue running with partial services
			} else {
				// All services failed or other error type
				startErr = err
				// If all services fail, shut down metrics server
				if a.metricsServer != nil {
					if shutdownErr := a.metricsServer.Shutdown(context.Background()); shutdownErr != nil {
						slog.Error("failed to shutdown metrics server", "error", shutdownErr)
					}
				}
				return
			}
		}
	})

	return startErr
}

// Shutdown gracefully shuts down the application
func (a *App) Shutdown(ctx context.Context) error {
	var shutdownErr error
	a.stopOnce.Do(func() {
		shutdownErr = a.performShutdown(ctx)
	})
	return shutdownErr
}

// performShutdown performs the actual shutdown sequence
func (a *App) performShutdown(ctx context.Context) error {
	var errs []error

	// Shutdown services
	if err := a.registry.Shutdown(ctx); err != nil {
		// The error from Shutdown is already typed
		errs = append(errs, err)
	}

	// Shutdown metrics server if running
	if a.metricsServer != nil {
		if err := a.metricsServer.Shutdown(ctx); err != nil {
			errs = append(errs, tserrors.WrapInternal(err, "failed to shutdown metrics server"))
		}
	}

	// Close tailscale server
	if err := a.tsServer.Close(); err != nil {
		errs = append(errs, tserrors.WrapResource(err, "failed to close tailscale server"))
	}

	if len(errs) == 0 {
		slog.Info("shutdown complete")
		return nil
	}

	// Combine all errors using errors.Join
	return errors.Join(errs...)
}

// MetricsAddr returns the actual address the metrics server is listening on.
// Returns empty string if metrics server is not running.
func (a *App) MetricsAddr() string {
	if a.metricsServer == nil {
		return ""
	}
	return a.metricsServer.Addr()
}
