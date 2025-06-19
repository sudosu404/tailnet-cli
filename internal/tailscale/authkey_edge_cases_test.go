package tailscale

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jtdowney/tsbridge/internal/config"
	"github.com/jtdowney/tsbridge/internal/tsnet"
)

func TestAuthKeyOptimizationEdgeCases(t *testing.T) {
	t.Run("multiple services with mixed state", func(t *testing.T) {
		// Track OAuth calls per service
		oauthCalls := make(map[string]int)

		// Mock OAuth server
		oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v2/oauth/token":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "mock-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			case "/api/v2/tailnet/-/keys":
				// Track which service is making the call based on request
				// In a real scenario, we might parse the request to determine this
				// For this test, we'll just count total calls
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"key":     "tskey-auth-mixed",
					"created": time.Now().Format(time.RFC3339),
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer oauthServer.Close()

		t.Setenv("TSBRIDGE_OAUTH_ENDPOINT", oauthServer.URL)

		// Create state directory
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, "tsbridge-state")

		// Create state for some services but not others
		services := []struct {
			name     string
			hasState bool
		}{
			{"service-with-state-1", true},
			{"service-without-state-1", false},
			{"service-with-state-2", true},
			{"service-without-state-2", false},
		}

		// Set up state files for services that should have them
		for _, svc := range services {
			if svc.hasState {
				serviceDir := filepath.Join(stateDir, svc.name)
				if err := os.MkdirAll(serviceDir, 0755); err != nil {
					t.Fatalf("failed to create state dir for %s: %v", svc.name, err)
				}
				stateFile := filepath.Join(serviceDir, "tailscaled.state")
				if err := os.WriteFile(stateFile, []byte("mock-state"), 0644); err != nil {
					t.Fatalf("failed to create state file for %s: %v", svc.name, err)
				}
			}
		}

		// Configure server
		cfg := config.Tailscale{
			OAuthClientID:     "test-client-id",
			OAuthClientSecret: "test-client-secret",
			StateDir:          stateDir,
		}

		// Track auth keys set for each service
		authKeys := make(map[string]string)
		var totalOAuthCalls int

		// Mock factory
		factory := func() tsnet.TSNetServer {
			mock := tsnet.NewMockTSNetServer()
			mock.StartFunc = func() error {
				// Track auth key for this service
				authKeys[mock.Hostname] = mock.AuthKey
				if mock.AuthKey != "" {
					totalOAuthCalls++
					oauthCalls[mock.Hostname]++
				}
				return nil
			}
			mock.ListenTLSFunc = func(network, addr string) (net.Listener, error) {
				ln, _ := net.Listen("tcp", "127.0.0.1:0")
				return ln, nil
			}
			return mock
		}

		server, err := NewServerWithFactory(cfg, factory)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		defer server.Close()

		// Create listeners for all services
		for _, svc := range services {
			listener, err := server.Listen(svc.name, "auto", false)
			if err != nil {
				t.Fatalf("failed to create listener for %s: %v", svc.name, err)
			}
			listener.Close()
		}

		// Verify auth keys were only generated for services without state
		for _, svc := range services {
			authKey := authKeys[svc.name]
			if svc.hasState && authKey != "" {
				t.Errorf("service %s has state but auth key was generated: %s", svc.name, authKey)
			}
			if !svc.hasState && authKey == "" {
				t.Errorf("service %s has no state but auth key was not generated", svc.name)
			}
		}

		// Verify OAuth was only called for services without state
		expectedCalls := 0
		for _, svc := range services {
			if !svc.hasState {
				expectedCalls++
			}
		}
		if totalOAuthCalls != expectedCalls {
			t.Errorf("expected %d OAuth calls, got %d", expectedCalls, totalOAuthCalls)
		}
	})

	t.Run("state file permissions error", func(t *testing.T) {
		// This test verifies that if we can't read the state file,
		// we fall back to generating an auth key
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, "tsbridge-state")
		serviceName := "test-service"
		serviceDir := filepath.Join(stateDir, serviceName)

		// Create state directory
		if err := os.MkdirAll(serviceDir, 0755); err != nil {
			t.Fatalf("failed to create state directory: %v", err)
		}

		// Create state file with no read permissions
		stateFile := filepath.Join(serviceDir, "tailscaled.state")
		if err := os.WriteFile(stateFile, []byte("mock-state"), 0644); err != nil {
			t.Fatalf("failed to create state file: %v", err)
		}

		// Make the file unreadable (but os.Stat still works)
		if err := os.Chmod(stateFile, 0000); err != nil {
			t.Fatalf("failed to change permissions: %v", err)
		}
		defer os.Chmod(stateFile, 0644) // Clean up

		// The hasExistingState function uses os.Stat which checks existence
		// not readability, so it will still return true
		result := hasExistingState(stateDir, serviceName)
		if !result {
			t.Error("expected hasExistingState to return true even when state file is unreadable (os.Stat still works)")
		}
	})

	t.Run("auth key from config when state doesn't exist", func(t *testing.T) {
		// Test that non-OAuth auth keys still work for new services
		tmpDir := t.TempDir()
		stateDir := filepath.Join(tmpDir, "tsbridge-state")
		serviceName := "new-service"

		cfg := config.Tailscale{
			AuthKey:  "tskey-static-auth",
			StateDir: stateDir,
		}

		var capturedAuthKey string
		factory := func() tsnet.TSNetServer {
			mock := tsnet.NewMockTSNetServer()
			mock.StartFunc = func() error {
				capturedAuthKey = mock.AuthKey
				return nil
			}
			mock.ListenTLSFunc = func(network, addr string) (net.Listener, error) {
				ln, _ := net.Listen("tcp", "127.0.0.1:0")
				return ln, nil
			}
			return mock
		}

		server, err := NewServerWithFactory(cfg, factory)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		defer server.Close()

		listener, err := server.Listen(serviceName, "auto", false)
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		listener.Close()

		// Verify static auth key was used
		if capturedAuthKey != "tskey-static-auth" {
			t.Errorf("expected static auth key, got %s", capturedAuthKey)
		}
	})
}
