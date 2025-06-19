package app

import (
	"testing"

	"github.com/jtdowney/tsbridge/internal/config"
	"github.com/jtdowney/tsbridge/internal/tailscale"
	tsnet "github.com/jtdowney/tsbridge/internal/tsnet"
)

// createMockTailscaleServer creates a mock tailscale server for testing
func createMockTailscaleServer(t *testing.T, cfg config.Tailscale) *tailscale.Server {
	t.Helper()

	factory := func() tsnet.TSNetServer {
		return tsnet.NewMockTSNetServer()
	}

	server, err := tailscale.NewServerWithFactory(cfg, factory)
	if err != nil {
		t.Fatalf("failed to create mock tailscale server: %v", err)
	}

	return server
}
