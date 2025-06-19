package helpers

import (
	"testing"
	"time"

	"github.com/jtdowney/tsbridge/internal/testutil"
)

func TestNewTestFixture(t *testing.T) {
	fixture := NewTestFixture(t)
	cfg := fixture.Build()

	// Verify defaults
	testutil.AssertEqual(t, "tskey-auth-test123", cfg.Tailscale.AuthKey)
	testutil.AssertEqual(t, "localhost:0", cfg.Global.MetricsAddr)
	testutil.AssertEqual(t, 1, len(cfg.Services))
	testutil.AssertEqual(t, "test-service", cfg.Services[0].Name)
	testutil.AssertEqual(t, "localhost:8080", cfg.Services[0].BackendAddr)
}

func TestTestFixtureWithService(t *testing.T) {
	fixture := NewTestFixture(t)

	// Test updating existing service
	cfg := fixture.WithService("test-service", "localhost:9090").Build()
	testutil.AssertEqual(t, 1, len(cfg.Services))
	testutil.AssertEqual(t, "localhost:9090", cfg.Services[0].BackendAddr)

	// Test adding new service
	cfg = fixture.WithService("another-service", "localhost:9091").Build()
	testutil.AssertEqual(t, 2, len(cfg.Services))
	testutil.AssertEqual(t, "another-service", cfg.Services[1].Name)
	testutil.AssertEqual(t, "localhost:9091", cfg.Services[1].BackendAddr)
}

func TestTestFixtureWithOAuth(t *testing.T) {
	fixture := NewTestFixture(t)
	cfg := fixture.WithOAuth("client-id", "client-secret").Build()

	// Verify OAuth is configured and AuthKey is cleared
	testutil.AssertEqual(t, "", cfg.Tailscale.AuthKey)
	testutil.AssertEqual(t, "client-id", cfg.Tailscale.OAuthClientID)
	testutil.AssertEqual(t, "client-secret", cfg.Tailscale.OAuthClientSecret)
}

func TestTestFixtureWithTimeout(t *testing.T) {
	fixture := NewTestFixture(t)
	cfg := fixture.
		WithTimeout("read", 5*time.Second).
		WithTimeout("write", 10*time.Second).
		WithTimeout("idle", 15*time.Second).
		WithTimeout("shutdown", 20*time.Second).
		Build()

	testutil.AssertEqual(t, 5*time.Second, cfg.Global.ReadTimeout.Duration)
	testutil.AssertEqual(t, 10*time.Second, cfg.Global.WriteTimeout.Duration)
	testutil.AssertEqual(t, 15*time.Second, cfg.Global.IdleTimeout.Duration)
	testutil.AssertEqual(t, 20*time.Second, cfg.Global.ShutdownTimeout.Duration)
}
