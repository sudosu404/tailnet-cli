// Package helpers provides common test utilities for integration tests.
package helpers

import (
	"testing"
	"time"

	"github.com/sudosu404/tailnet-cli/internal/config"
	"github.com/sudosu404/tailnet-cli/internal/testhelpers"
)

// TestFixture provides a standard configuration builder for tests
type TestFixture struct {
	t   *testing.T
	cfg *config.Config
}

// NewTestFixture creates a new test fixture with minimal defaults
func NewTestFixture(t *testing.T) *TestFixture {
	t.Helper()

	boolFalse := false
	return &TestFixture{
		t: t,
		cfg: &config.Config{
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
					Name:         "test-service",
					BackendAddr:  "localhost:8080",
					TLSMode:      "off",
					WhoisEnabled: &boolFalse,
				},
			},
		},
	}
}

// WithService adds or updates a service configuration
func (f *TestFixture) WithService(name, backendAddr string) *TestFixture {
	// Check if service exists
	for i, svc := range f.cfg.Services {
		if svc.Name == name {
			f.cfg.Services[i].BackendAddr = backendAddr
			return f
		}
	}

	// Add new service
	boolFalse := false
	f.cfg.Services = append(f.cfg.Services, config.Service{
		Name:         name,
		BackendAddr:  backendAddr,
		TLSMode:      "off",
		WhoisEnabled: &boolFalse,
	})
	return f
}

// WithOAuth configures OAuth authentication
func (f *TestFixture) WithOAuth(clientID, clientSecret string) *TestFixture {
	f.cfg.Tailscale.AuthKey = config.RedactedString("")
	f.cfg.Tailscale.OAuthClientID = clientID
	f.cfg.Tailscale.OAuthClientSecret = config.RedactedString(clientSecret)
	return f
}

// WithTimeout sets a specific timeout value
func (f *TestFixture) WithTimeout(name string, duration time.Duration) *TestFixture {
	switch name {
	case "read":
		f.cfg.Global.ReadHeaderTimeout = testhelpers.DurationPtr(duration)
	case "write":
		f.cfg.Global.WriteTimeout = testhelpers.DurationPtr(duration)
	case "idle":
		f.cfg.Global.IdleTimeout = testhelpers.DurationPtr(duration)
	case "shutdown":
		f.cfg.Global.ShutdownTimeout = testhelpers.DurationPtr(duration)
	}
	return f
}

// Build returns the configured Config
func (f *TestFixture) Build() *config.Config {
	return f.cfg
}
