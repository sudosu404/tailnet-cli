package tailscale

import (
	"context"
	"fmt"

	tsnetpkg "github.com/sudosu404/tailnet-cli/internal/tsnet"
	"tailscale.com/client/tailscale/apitype"
)

// WhoisClientAdapter adapts a TSNetServer to implement the middleware.WhoisClient interface
type WhoisClientAdapter struct {
	server tsnetpkg.TSNetServer
}

// NewWhoisClientAdapter creates a new adapter for the given TSNetServer
func NewWhoisClientAdapter(server tsnetpkg.TSNetServer) *WhoisClientAdapter {
	return &WhoisClientAdapter{server: server}
}

// WhoIs performs a whois lookup for the given remote address
func (w *WhoisClientAdapter) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	// Get the local client from the tsnet server
	lc, err := w.server.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("getting local client: %w", err)
	}

	// Use the local client to perform the whois lookup
	// Now this returns the full apitype.WhoIsResponse directly
	return lc.WhoIs(ctx, remoteAddr)
}
