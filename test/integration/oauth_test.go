package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jtdowney/tsbridge/internal/config"
	"github.com/jtdowney/tsbridge/test/integration/helpers"
)

// TestInMemoryOAuthConfiguration was removed as it was redundant with TestInMemoryServiceWithInvalidBackend
// OAuth configuration doesn't affect backend validation, so this test added no value

// TestE2EFullStartupWithOAuth tests the complete startup flow with OAuth authentication using exec.Command
func TestE2EFullStartupWithOAuth(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Mock OAuth server
	oauthCalls := 0
	authKeyCalls := 0

	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			oauthCalls++
			if r.Method != "POST" {
				t.Errorf("expected POST to /api/v2/oauth/token, got %s", r.Method)
			}
			// OAuth2 library sends credentials as Basic Auth
			username, password, ok := r.BasicAuth()
			if !ok {
				t.Error("expected Basic Auth header")
			}
			if username != "test-client-id" {
				t.Errorf("expected client_id 'test-client-id', got %s", username)
			}
			if password != "test-client-secret" {
				t.Errorf("expected client_secret 'test-client-secret', got %s", password)
			}
			// Also check for grant_type in form
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}
			if r.PostForm.Get("grant_type") != "client_credentials" {
				t.Errorf("expected grant_type 'client_credentials', got %s", r.PostForm.Get("grant_type"))
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600}`))

		case "/api/v2/tailnet/-/keys":
			authKeyCalls++
			if r.Method != "POST" {
				t.Errorf("expected POST to /api/v2/tailnet/-/keys, got %s", r.Method)
			}
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-token" {
				t.Errorf("expected Authorization header 'Bearer test-token', got %s", auth)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"key": "tskey-auth-test123", "created": "2024-01-01T00:00:00Z"}`))

		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer oauthServer.Close()

	// Create test backend first
	backend := helpers.CreateTestBackend(t)

	// Create config with OAuth using helper
	cfg := helpers.NewTestFixture(t).
		WithOAuth("test-client-id", "test-client-secret").
		WithService("test-oauth-service", backend.Listener.Addr().String()).
		Build()

	// Add OAuth tags and adjust whois timeout
	cfg.Tailscale.OAuthTags = []string{"tag:test", "tag:integration"}
	cfg.Services[0].WhoisTimeout = config.Duration{Duration: 100 * time.Millisecond}

	// Write config file using helper
	configPath := helpers.WriteConfigFile(t, cfg)

	// Set the OAuth endpoint to our mock server
	os.Setenv("TSBRIDGE_OAUTH_ENDPOINT", oauthServer.URL)
	defer os.Unsetenv("TSBRIDGE_OAUTH_ENDPOINT")

	// Build the binary using helper
	binPath := helpers.BuildTestBinary(t)

	// Start tsbridge with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "-config", configPath, "-verbose")
	cmd.Env = append(os.Environ(), "TSBRIDGE_OAUTH_ENDPOINT="+oauthServer.URL)

	// Capture output
	output, err := cmd.CombinedOutput()

	// We expect it to timeout (since it's a long-running server)
	// but OAuth should have been called
	if err != nil && ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("unexpected error: %v\n%s", err, output)
	}

	// Give it a moment to process
	time.Sleep(200 * time.Millisecond)

	// Check that OAuth flow was triggered
	if oauthCalls == 0 {
		t.Errorf("expected OAuth token endpoint to be called, output:\n%s", output)
	}
	if authKeyCalls == 0 {
		t.Errorf("expected auth key creation endpoint to be called, output:\n%s", output)
	}

	// Verify the server attempted to start
	outputStr := string(output)
	if outputStr == "" {
		t.Error("expected some output from tsbridge")
	}
}
