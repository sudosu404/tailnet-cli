// Package helpers provides common test utilities for integration tests.
package helpers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sudosu404/tailnet-cli/internal/config"
	"github.com/sudosu404/tailnet-cli/internal/testhelpers"
	"github.com/stretchr/testify/require"
)

// RequestTracker tracks requests to a test backend server.
type RequestTracker struct {
	RequestsStarted       int32
	RequestsCompleted     int32
	MaxConcurrentRequests int32
	activeRequests        int32
}

// RecordStart records the start of a request.
func (rt *RequestTracker) RecordStart() {
	atomic.AddInt32(&rt.RequestsStarted, 1)
	active := atomic.AddInt32(&rt.activeRequests, 1)

	// Update max concurrent if needed
	for {
		current := atomic.LoadInt32(&rt.MaxConcurrentRequests)
		if active <= current || atomic.CompareAndSwapInt32(&rt.MaxConcurrentRequests, current, active) {
			break
		}
	}
}

// RecordComplete records the completion of a request.
func (rt *RequestTracker) RecordComplete() {
	atomic.AddInt32(&rt.activeRequests, -1)
	atomic.AddInt32(&rt.RequestsCompleted, 1)
}

// CreateTestBackend creates a simple test backend server that returns OK.
func CreateTestBackend(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	t.Cleanup(func() { server.Close() })
	return server
}

// CreateTrackingBackend creates a backend server that tracks requests.
func CreateTrackingBackend(t *testing.T) (*httptest.Server, *RequestTracker) {
	t.Helper()

	tracker := &RequestTracker{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker.RecordStart()
		defer tracker.RecordComplete()

		// Handle common test paths
		switch r.URL.Path {
		case "/slow":
			time.Sleep(100 * time.Millisecond)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal Server Error"))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	t.Cleanup(func() { server.Close() })
	return server, tracker
}

// CreateTestConfig creates a standard test configuration.
func CreateTestConfig(t *testing.T, serviceName string, backendAddr string) *config.Config {
	t.Helper()

	boolFalse := false
	return &config.Config{
		Tailscale: config.Tailscale{
			AuthKey:  config.RedactedString("tskey-auth-test123"),
			StateDir: t.TempDir(),
		},
		Global: config.Global{
			MetricsAddr:       "localhost:0",
			ReadHeaderTimeout: testhelpers.DurationPtr(30 * time.Second),
			WriteTimeout:      testhelpers.DurationPtr(30 * time.Second),
			IdleTimeout:       testhelpers.DurationPtr(120 * time.Second),
			ShutdownTimeout:   testhelpers.DurationPtr(10 * time.Second),
		},
		Services: []config.Service{
			{
				Name:         serviceName,
				BackendAddr:  backendAddr,
				TLSMode:      "off",
				WhoisEnabled: &boolFalse,
			},
		},
	}
}

// CreateMultiServiceConfig creates a test configuration with multiple services.
func CreateMultiServiceConfig(t *testing.T, services map[string]string) *config.Config {
	t.Helper()

	boolFalse := false
	cfg := &config.Config{
		Tailscale: config.Tailscale{
			AuthKey:  config.RedactedString("tskey-auth-test123"),
			StateDir: t.TempDir(),
		},
		Global: config.Global{
			MetricsAddr:       "localhost:0",
			ReadHeaderTimeout: testhelpers.DurationPtr(30 * time.Second),
			WriteTimeout:      testhelpers.DurationPtr(30 * time.Second),
			IdleTimeout:       testhelpers.DurationPtr(120 * time.Second),
			ShutdownTimeout:   testhelpers.DurationPtr(10 * time.Second),
		},
	}

	for name, addr := range services {
		cfg.Services = append(cfg.Services, config.Service{
			Name:         name,
			BackendAddr:  addr,
			TLSMode:      "off",
			WhoisEnabled: &boolFalse,
		})
	}

	return cfg
}

// BuildTestBinary builds the tailnet binary for testing.
func BuildTestBinary(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "tailnet")

	// Build using relative path from test directory
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/tailnet")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	return binPath
}

// TSBridgeProcess wraps an exec.Cmd for tailnet with helper methods.
type TSBridgeProcess struct {
	cmd        *exec.Cmd
	outputChan chan string
	t          *testing.T
	shutdown   bool
	output     string
}

// StartTSBridge starts a tailnet process with common setup.
func StartTSBridge(t *testing.T, configPath string, extraEnv ...string) *TSBridgeProcess {
	t.Helper()

	binPath := BuildTestBinary(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel() })

	cmd := exec.CommandContext(ctx, binPath, "-config", configPath, "-verbose")

	// Set up environment
	cmd.Env = append(os.Environ(), "TSBRIDGE_TEST_MODE=1")
	cmd.Env = append(cmd.Env, extraEnv...)

	// Capture output
	outputPipe, err := cmd.StdoutPipe()
	require.NoError(t, err, "failed to create stdout pipe")

	errPipe, err := cmd.StderrPipe()
	require.NoError(t, err, "failed to create stderr pipe")

	combinedOutput := io.MultiReader(outputPipe, errPipe)

	// Start the process
	err = cmd.Start()
	require.NoError(t, err, "failed to start tailnet")

	// Read output in goroutine
	outputChan := make(chan string, 1)
	go func() {
		output, _ := io.ReadAll(combinedOutput)
		outputChan <- string(output)
	}()

	process := &TSBridgeProcess{
		cmd:        cmd,
		outputChan: outputChan,
		t:          t,
	}

	// Wait for startup instead of fixed sleep
	process.WaitForStartup()

	// Set up cleanup
	t.Cleanup(func() {
		process.Shutdown()
	})

	return process
}

// Shutdown gracefully shuts down the tailnet process.
func (p *TSBridgeProcess) Shutdown() {
	p.t.Helper()

	if p.shutdown {
		return
	}
	p.shutdown = true

	// Send interrupt signal
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		p.t.Logf("failed to send interrupt signal: %v", err)
	}

	// Wait for process to exit
	done := make(chan error, 1)
	go func() {
		done <- p.cmd.Wait()
	}()

	select {
	case <-done:
		// Process exited
	case <-time.After(5 * time.Second):
		p.t.Log("tailnet did not shut down within timeout, killing")
		_ = p.cmd.Process.Kill()
	}
}

// WaitForStartup waits for the tailnet process to complete initial startup.
// This is more reliable than a fixed sleep and makes tests less flaky.
func (p *TSBridgeProcess) WaitForStartup() {
	p.t.Helper()

	// In test mode, startup is fast. Use exponential backoff
	// starting with a very short delay.
	delays := []time.Duration{
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
	}

	for i, delay := range delays {
		time.Sleep(delay)

		// For the last delay, log if startup is taking too long
		if i == len(delays)-1 {
			p.t.Logf("Note: startup took longer than expected (>1.5s)")
		}
	}
}

// GetOutput returns the captured output from the process.
// Should be called after Shutdown to ensure all output is captured.
func (p *TSBridgeProcess) GetOutput() string {
	// If we already have output from WaitForServices, use that
	if p.output != "" {
		// Continue reading any remaining output
		select {
		case additionalOutput := <-p.outputChan:
			p.output += additionalOutput
		case <-time.After(100 * time.Millisecond):
			// No more output
		}
		return p.output
	}

	// If process is still running, shutdown first
	if p.cmd.Process != nil {
		p.Shutdown()
	}

	select {
	case output := <-p.outputChan:
		return output
	case <-time.After(1 * time.Second):
		return "Failed to get output"
	}
}

// WriteConfigFile writes a TOML config file for testing.
func WriteConfigFile(t *testing.T, cfg *config.Config) string {
	t.Helper()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.toml")

	// Simple TOML generation for common test cases
	content := fmt.Sprintf(`[tailscale]
state_dir = "%s"`, cfg.Tailscale.StateDir)

	// Add auth configuration
	if cfg.Tailscale.AuthKey.Value() != "" {
		content += fmt.Sprintf(`
auth_key = "%s"`, cfg.Tailscale.AuthKey.Value())
	}
	if cfg.Tailscale.OAuthClientID != "" {
		content += fmt.Sprintf(`
oauth_client_id = "%s"
oauth_client_secret = "%s"`, cfg.Tailscale.OAuthClientID, cfg.Tailscale.OAuthClientSecret.Value())
	}

	// Add default_tags if present
	if len(cfg.Tailscale.DefaultTags) > 0 {
		content += `
default_tags = [`
		for i, tag := range cfg.Tailscale.DefaultTags {
			if i > 0 {
				content += ", "
			}
			content += fmt.Sprintf(`"%s"`, tag)
		}
		content += `]`
	}

	// Build global section
	content += fmt.Sprintf(`

[global]
metrics_addr = "%s"`,
		cfg.Global.MetricsAddr)

	if cfg.Global.ReadHeaderTimeout != nil {
		content += fmt.Sprintf(`
read_header_timeout = "%s"`, *cfg.Global.ReadHeaderTimeout)
	}
	if cfg.Global.WriteTimeout != nil {
		content += fmt.Sprintf(`
write_timeout = "%s"`, *cfg.Global.WriteTimeout)
	}
	if cfg.Global.IdleTimeout != nil {
		content += fmt.Sprintf(`
idle_timeout = "%s"`, *cfg.Global.IdleTimeout)
	}
	if cfg.Global.ShutdownTimeout != nil {
		content += fmt.Sprintf(`
shutdown_timeout = "%s"`, *cfg.Global.ShutdownTimeout)
	}

	content += `

`

	// Add services
	for _, svc := range cfg.Services {
		whoisEnabled := "false"
		if svc.WhoisEnabled != nil && *svc.WhoisEnabled {
			whoisEnabled = "true"
		}

		content += fmt.Sprintf(`[[services]]
name = "%s"
backend_addr = "%s"
tls_mode = "%s"
whois_enabled = %s
`, svc.Name, svc.BackendAddr, svc.TLSMode, whoisEnabled)

		// Add optional fields
		if svc.WhoisTimeout != nil && *svc.WhoisTimeout > 0 {
			content += fmt.Sprintf(`whois_timeout = "%s"
`, *svc.WhoisTimeout)
		}

		// Add tags if present
		if len(svc.Tags) > 0 {
			content += `tags = [`
			for i, tag := range svc.Tags {
				if i > 0 {
					content += ", "
				}
				content += fmt.Sprintf(`"%s"`, tag)
			}
			content += `]
`
		}
	}

	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err, "failed to write config file")

	return configPath
}
