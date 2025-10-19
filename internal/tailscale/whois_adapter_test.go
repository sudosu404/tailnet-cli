package tailscale

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sudosu404/tailnet-cli/internal/tsnet"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// TestWhoisClientAdapter_PreservesFullResponse verifies that WhoisClientAdapter
// correctly passes through all fields from the WhoIs response without data loss
func TestWhoisClientAdapter_PreservesFullResponse(t *testing.T) {
	// Create test data with all fields populated
	addr1 := netip.MustParsePrefix("100.64.0.1/32")
	addr2 := netip.MustParsePrefix("fd7a:115c:a1e0::1/128")

	expectedResponse := &apitype.WhoIsResponse{
		UserProfile: &tailcfg.UserProfile{
			LoginName:   "user@example.com",
			DisplayName: "Test User",
		},
		Node: &tailcfg.Node{
			Name:      "test-node",
			Addresses: []netip.Prefix{addr1, addr2},
		},
	}

	// Create a mock server that returns the full response
	mockServer := tsnet.NewMockTSNetServer()
	mockServer.LocalClientFunc = func() (tsnet.LocalClient, error) {
		return &tsnet.MockLocalClient{
			WhoIsFunc: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
				// Now we can return the full apitype.WhoIsResponse
				return expectedResponse, nil
			},
		}, nil
	}

	adapter := NewWhoisClientAdapter(mockServer)
	resp, err := adapter.WhoIs(context.Background(), "100.64.0.1:12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all fields are preserved
	if resp.UserProfile == nil {
		t.Fatal("UserProfile should not be nil")
	}
	if resp.UserProfile.LoginName != "user@example.com" {
		t.Errorf("LoginName = %q, want %q", resp.UserProfile.LoginName, "user@example.com")
	}
	if resp.UserProfile.DisplayName != "Test User" {
		t.Errorf("DisplayName = %q, want %q", resp.UserProfile.DisplayName, "Test User")
	}

	if resp.Node == nil {
		t.Fatal("Node should not be nil")
	}
	if resp.Node.Name != "test-node" {
		t.Errorf("Node.Name = %q, want %q", resp.Node.Name, "test-node")
	}
	if len(resp.Node.Addresses) != 2 {
		t.Errorf("Addresses length = %d, want 2", len(resp.Node.Addresses))
	} else {
		if resp.Node.Addresses[0] != addr1 {
			t.Errorf("Addresses[0] = %v, want %v", resp.Node.Addresses[0], addr1)
		}
		if resp.Node.Addresses[1] != addr2 {
			t.Errorf("Addresses[1] = %v, want %v", resp.Node.Addresses[1], addr2)
		}
	}

	// These fields are now properly preserved for the middleware to use
	// in X-Tailscale-Name and X-Tailscale-Addresses headers
}
