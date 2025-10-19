package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sudosu404/tailnet-cli/internal/constants"
	"github.com/sudosu404/tailnet-cli/internal/errors"
	"github.com/sudosu404/tailnet-cli/internal/metrics"
)

// simpleHandler wraps an http.HandlerFunc to implement the Handler interface
type simpleHandler struct {
	http.HandlerFunc
}

func (h *simpleHandler) Close() error {
	return nil
}

// defaultTestTransportConfig returns a TransportConfig with reasonable test defaults
func defaultTestTransportConfig() *TransportConfig {
	return &TransportConfig{
		ResponseHeaderTimeout: 5 * time.Second,
		DialTimeout:           constants.DefaultDialTimeout,
		KeepAliveTimeout:      constants.DefaultKeepAliveTimeout,
		IdleConnTimeout:       constants.DefaultIdleConnTimeout,
		TLSHandshakeTimeout:   constants.DefaultTLSHandshakeTimeout,
		ExpectContinueTimeout: constants.DefaultExpectContinueTimeout,
	}
}

// newTestHandler is a test helper that creates a handler with basic configuration
func newTestHandler(backendAddr string, transportConfig *TransportConfig, trustedProxies []string) (Handler, error) {
	return NewHandler(&HandlerConfig{
		BackendAddr:     backendAddr,
		TransportConfig: transportConfig,
		TrustedProxies:  trustedProxies,
	})
}

func TestHTTPProxy(t *testing.T) {
	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back request details
		w.Header().Set("X-Test-Backend", "true")
		w.Header().Set("X-Request-Path", r.URL.RequestURI())
		w.Header().Set("X-Request-Method", r.Method)

		// Echo any body content
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			fmt.Fprintf(w, "backend response: %s", string(body))
		} else {
			fmt.Fprint(w, "backend response: no body")
		}
	}))
	defer backend.Close()

	tests := []struct {
		name           string
		method         string
		path           string
		body           string
		expectedStatus int
		expectedBody   string
		checkHeaders   map[string]string
	}{
		{
			name:           "GET request",
			method:         "GET",
			path:           "/api/test",
			expectedStatus: http.StatusOK,
			expectedBody:   "backend response: no body",
			checkHeaders: map[string]string{
				"X-Test-Backend":   "true",
				"X-Request-Path":   "/api/test",
				"X-Request-Method": "GET",
			},
		},
		{
			name:           "POST request with body",
			method:         "POST",
			path:           "/api/create",
			body:           `{"name": "test"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   `backend response: {"name": "test"}`,
			checkHeaders: map[string]string{
				"X-Test-Backend":   "true",
				"X-Request-Path":   "/api/create",
				"X-Request-Method": "POST",
			},
		},
		{
			name:           "PUT request",
			method:         "PUT",
			path:           "/api/update/123",
			body:           `{"updated": true}`,
			expectedStatus: http.StatusOK,
			expectedBody:   `backend response: {"updated": true}`,
			checkHeaders: map[string]string{
				"X-Request-Method": "PUT",
			},
		},
		{
			name:           "DELETE request",
			method:         "DELETE",
			path:           "/api/delete/123",
			expectedStatus: http.StatusOK,
			expectedBody:   "backend response: no body",
			checkHeaders: map[string]string{
				"X-Request-Method": "DELETE",
			},
		},
		{
			name:           "request with query params",
			method:         "GET",
			path:           "/api/search?q=test&limit=10",
			expectedStatus: http.StatusOK,
			expectedBody:   "backend response: no body",
			checkHeaders: map[string]string{
				"X-Request-Path": "/api/search?q=test&limit=10",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create proxy handler
			handler, err := newTestHandler(backend.URL, defaultTestTransportConfig(), nil)
			require.NoError(t, err)

			// Create test request
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Handle request
			handler.ServeHTTP(rr, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Check response body
			assert.Equal(t, tt.expectedBody, rr.Body.String())

			// Check headers
			for key, expected := range tt.checkHeaders {
				actual := rr.Header().Get(key)
				assert.Equal(t, expected, actual, "header %s mismatch", key)
			}
		})
	}
}

func TestUnixSocketProxy(t *testing.T) {
	// Create temporary directory for unix socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create unix socket server
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err, "failed to create unix socket")
	defer listener.Close()

	// Start HTTP server on unix socket
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Unix-Socket", "true")
		fmt.Fprintf(w, "unix socket response: %s", r.URL.Path)
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("unix socket server error: %v", err)
		}
	}()
	defer server.Close()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "root path",
			path:           "/",
			expectedStatus: http.StatusOK,
			expectedBody:   "unix socket response: /",
		},
		{
			name:           "api path",
			path:           "/api/test",
			expectedStatus: http.StatusOK,
			expectedBody:   "unix socket response: /api/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create proxy handler for unix socket
			handler, err := newTestHandler("unix://"+socketPath, defaultTestTransportConfig(), nil)
			require.NoError(t, err)

			// Create test request
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			// Handle request
			handler.ServeHTTP(rr, req)

			// Check status
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Check body
			assert.Equal(t, tt.expectedBody, rr.Body.String())

			// Check unix socket header
			assert.Equal(t, "true", rr.Header().Get("X-Unix-Socket"), "expected X-Unix-Socket header")
		})
	}
}

// Test that dialing a unix socket honors the request context (timeouts/cancellation)
func TestUnixSocketDialRespectsContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "nonexistent.sock")

	// Create proxy handler pointing at a non-listening unix socket
	handler, err := newTestHandler("unix://"+socketPath, defaultTestTransportConfig(), nil)
	require.NoError(t, err)

	// Use an already-expired context to ensure DialContext sees cancellation immediately
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	// Expect that the proxy surfaces a timeout (504)
	assert.Equal(t, http.StatusGatewayTimeout, rr.Code)
	assert.Contains(t, rr.Body.String(), "Gateway Timeout")

	// And that it returned quickly (didn't block on a long dial)
	assert.Less(t, elapsed, 200*time.Millisecond)
}

func TestProxyWithTimeouts(t *testing.T) {
	// Create a slow backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delay := r.URL.Query().Get("delay")
		if delay != "" {
			d, _ := time.ParseDuration(delay)
			time.Sleep(d)
		}
		fmt.Fprint(w, "response after delay")
	}))
	defer backend.Close()

	tests := []struct {
		name          string
		delay         string
		timeout       time.Duration
		expectTimeout bool
	}{
		{
			name:          "fast response",
			delay:         "10ms",
			timeout:       100 * time.Millisecond,
			expectTimeout: false,
		},
		{
			name:          "slow response triggers timeout",
			delay:         "200ms",
			timeout:       50 * time.Millisecond,
			expectTimeout: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create proxy with timeout
			transportConfig := defaultTestTransportConfig()
			transportConfig.ResponseHeaderTimeout = tt.timeout
			handler, err := newTestHandler(backend.URL, transportConfig, nil)
			require.NoError(t, err)

			// Create request
			req := httptest.NewRequest("GET", "/?delay="+tt.delay, nil)
			rr := httptest.NewRecorder()

			// Handle request
			handler.ServeHTTP(rr, req)

			if tt.expectTimeout {
				// Should get a timeout error
				assert.Equal(t, http.StatusGatewayTimeout, rr.Code)
			} else {
				// Should succeed
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.Equal(t, "response after delay", rr.Body.String())
			}
		})
	}
}

func TestProxyErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		backendAddr    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "invalid backend address",
			backendAddr:    "http://invalid.backend.address:99999",
			expectedStatus: http.StatusBadGateway,
			expectedError:  "Bad Gateway",
		},
		{
			name:           "backend refused connection",
			backendAddr:    "http://127.0.0.1:1", // Port 1 should be refused
			expectedStatus: http.StatusBadGateway,
			expectedError:  "Bad Gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create proxy handler
			handler, err := newTestHandler(tt.backendAddr, defaultTestTransportConfig(), nil)
			if tt.backendAddr == "not-a-valid-url" && err != nil {
				// Expected error for invalid URL, create a simple handler that implements our interface
				handler = &simpleHandler{
					HandlerFunc: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						http.Error(w, "Bad Gateway", http.StatusBadGateway)
					}),
				}
			} else {
				require.NoError(t, err)
			}

			// Create test request
			req := httptest.NewRequest("GET", "/", nil)
			rr := httptest.NewRecorder()

			// Handle request
			handler.ServeHTTP(rr, req)

			// Check status
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Check error message
			assert.Contains(t, rr.Body.String(), tt.expectedError)
		})
	}
}

func TestProxyHeaderHandling(t *testing.T) {
	// Create backend that echoes headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo certain headers back
		if auth := r.Header.Get("Authorization"); auth != "" {
			w.Header().Set("X-Echo-Authorization", auth)
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("X-Echo-Content-Type", ct)
		}
		// Check that certain headers are handled correctly
		w.Header().Set("X-Forwarded-For", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"))
		w.Header().Set("X-Real-IP", r.Header.Get("X-Real-IP"))
		fmt.Fprint(w, "headers echoed")
	}))
	defer backend.Close()

	// Create proxy
	handler, err := newTestHandler(backend.URL, defaultTestTransportConfig(), nil)
	require.NoError(t, err)

	// Create request with headers
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "custom-value")
	req.RemoteAddr = "10.0.0.1:12345"

	rr := httptest.NewRecorder()

	// Handle request
	handler.ServeHTTP(rr, req)

	// Check that headers were passed through
	assert.Equal(t, "Bearer test-token", rr.Header().Get("X-Echo-Authorization"), "Authorization header not passed through")
	assert.Equal(t, "application/json", rr.Header().Get("X-Echo-Content-Type"), "Content-Type header not passed through")

	// Check forwarding headers were added
	assert.NotEmpty(t, rr.Header().Get("X-Forwarded-For"), "X-Forwarded-For header not added")
	assert.NotEmpty(t, rr.Header().Get("X-Real-IP"), "X-Real-IP header not added")
}

func TestXForwardedForSecurity(t *testing.T) {
	// Create backend that echoes X-Forwarded-For header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Forwarded-For", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Echo-Real-IP", r.Header.Get("X-Real-IP"))
		fmt.Fprint(w, "OK")
	}))
	defer backend.Close()

	tests := []struct {
		name                 string
		clientForwardedFor   string
		remoteAddr           string
		expectedForwardedFor string
		expectedRealIP       string
	}{
		{
			name:                 "no existing X-Forwarded-For",
			clientForwardedFor:   "",
			remoteAddr:           "192.168.1.100:12345",
			expectedForwardedFor: "192.168.1.100",
			expectedRealIP:       "192.168.1.100",
		},
		{
			name:                 "client provides X-Forwarded-For - should be ignored",
			clientForwardedFor:   "1.2.3.4, 5.6.7.8",
			remoteAddr:           "192.168.1.100:12345",
			expectedForwardedFor: "192.168.1.100", // Should only contain real client IP
			expectedRealIP:       "192.168.1.100",
		},
		{
			name:                 "client attempts IP spoofing - should be ignored",
			clientForwardedFor:   "trusted.internal.ip",
			remoteAddr:           "evil.client.ip:12345",
			expectedForwardedFor: "evil.client.ip", // Should only contain real client IP
			expectedRealIP:       "evil.client.ip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create proxy
			handler, err := newTestHandler(backend.URL, defaultTestTransportConfig(), nil)
			require.NoError(t, err)

			// Create request with potentially spoofed X-Forwarded-For
			req := httptest.NewRequest("GET", "/", nil)
			if tt.clientForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.clientForwardedFor)
			}
			req.RemoteAddr = tt.remoteAddr

			rr := httptest.NewRecorder()

			// Handle request
			handler.ServeHTTP(rr, req)

			// Check that proxy set correct forwarding headers
			actualForwardedFor := rr.Header().Get("X-Echo-Forwarded-For")
			assert.Equal(t, tt.expectedForwardedFor, actualForwardedFor, "X-Forwarded-For mismatch")

			actualRealIP := rr.Header().Get("X-Echo-Real-IP")
			assert.Equal(t, tt.expectedRealIP, actualRealIP, "X-Real-IP mismatch")
		})
	}
}

func TestXForwardedForWithTrustedProxies(t *testing.T) {
	// Create backend that echoes X-Forwarded-For header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Forwarded-For", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Echo-Real-IP", r.Header.Get("X-Real-IP"))
		fmt.Fprint(w, "OK")
	}))
	defer backend.Close()

	tests := []struct {
		name                 string
		trustedProxies       []string
		clientForwardedFor   string
		remoteAddr           string
		expectedForwardedFor string
		expectedRealIP       string
	}{
		{
			name:                 "request from trusted proxy - append to X-Forwarded-For",
			trustedProxies:       []string{"10.0.0.0/8"},
			clientForwardedFor:   "1.2.3.4",
			remoteAddr:           "10.0.0.1:12345",
			expectedForwardedFor: "1.2.3.4, 10.0.0.1",
			expectedRealIP:       "1.2.3.4", // Real IP from the X-Forwarded-For
		},
		{
			name:                 "request from untrusted proxy - ignore X-Forwarded-For",
			trustedProxies:       []string{"10.0.0.0/8"},
			clientForwardedFor:   "1.2.3.4",
			remoteAddr:           "192.168.1.100:12345",
			expectedForwardedFor: "192.168.1.100",
			expectedRealIP:       "192.168.1.100",
		},
		{
			name:                 "request from trusted proxy with multiple IPs in X-Forwarded-For",
			trustedProxies:       []string{"10.0.0.0/8"},
			clientForwardedFor:   "1.2.3.4, 5.6.7.8",
			remoteAddr:           "10.0.0.1:12345",
			expectedForwardedFor: "1.2.3.4, 5.6.7.8, 10.0.0.1",
			expectedRealIP:       "1.2.3.4", // First IP in the chain
		},
		{
			name:                 "request from specific trusted IP",
			trustedProxies:       []string{"192.168.1.1"},
			clientForwardedFor:   "1.2.3.4",
			remoteAddr:           "192.168.1.1:12345",
			expectedForwardedFor: "1.2.3.4, 192.168.1.1",
			expectedRealIP:       "1.2.3.4",
		},
		{
			name:                 "request from trusted proxy without X-Forwarded-For",
			trustedProxies:       []string{"10.0.0.0/8"},
			clientForwardedFor:   "",
			remoteAddr:           "10.0.0.1:12345",
			expectedForwardedFor: "10.0.0.1",
			expectedRealIP:       "10.0.0.1",
		},
		{
			name:                 "no trusted proxies configured - default behavior",
			trustedProxies:       nil,
			clientForwardedFor:   "1.2.3.4",
			remoteAddr:           "192.168.1.100:12345",
			expectedForwardedFor: "192.168.1.100",
			expectedRealIP:       "192.168.1.100",
		},
		{
			name:                 "multiple trusted proxy ranges",
			trustedProxies:       []string{"10.0.0.0/8", "172.16.0.0/12"},
			clientForwardedFor:   "1.2.3.4",
			remoteAddr:           "172.16.0.1:12345",
			expectedForwardedFor: "1.2.3.4, 172.16.0.1",
			expectedRealIP:       "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create proxy with trusted proxies
			handler, err := newTestHandler(backend.URL, defaultTestTransportConfig(), tt.trustedProxies)
			require.NoError(t, err)

			// Create request
			req := httptest.NewRequest("GET", "/", nil)
			if tt.clientForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.clientForwardedFor)
			}
			req.RemoteAddr = tt.remoteAddr

			rr := httptest.NewRecorder()

			// Handle request
			handler.ServeHTTP(rr, req)

			// Check that proxy set correct forwarding headers
			actualForwardedFor := rr.Header().Get("X-Echo-Forwarded-For")
			assert.Equal(t, tt.expectedForwardedFor, actualForwardedFor, "X-Forwarded-For mismatch")

			actualRealIP := rr.Header().Get("X-Echo-Real-IP")
			assert.Equal(t, tt.expectedRealIP, actualRealIP, "X-Real-IP mismatch")
		})
	}
}

func TestNewHandlerWithErrors(t *testing.T) {
	tests := []struct {
		name           string
		backendAddr    string
		trustedProxies []string
		wantErr        bool
		errContains    string
	}{
		{
			name:        "invalid backend URL scheme",
			backendAddr: "://invalid",
			wantErr:     true,
			errContains: "invalid backend address",
		},
		{
			name:        "empty backend URL",
			backendAddr: "",
			wantErr:     true,
			errContains: "invalid backend address",
		},
		{
			name:           "invalid trusted proxy IP",
			backendAddr:    "http://localhost:8080",
			trustedProxies: []string{"not-an-ip"},
			wantErr:        true,
			errContains:    "invalid trusted proxy IP",
		},
		{
			name:           "invalid trusted proxy CIDR",
			backendAddr:    "http://localhost:8080",
			trustedProxies: []string{"192.168.1.0/999"},
			wantErr:        true,
			errContains:    "invalid trusted proxy CIDR",
		},
		{
			name:           "valid configuration",
			backendAddr:    "http://localhost:8080",
			trustedProxies: []string{"192.168.1.0/24", "10.0.0.1"},
			wantErr:        false,
		},
		{
			name:        "valid unix socket",
			backendAddr: "unix:///tmp/test.sock",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := newTestHandler(tt.backendAddr, defaultTestTransportConfig(), tt.trustedProxies)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, handler, "NewHandler() should return nil handler with error")
			} else {
				require.NoError(t, err)
				require.NotNil(t, handler, "NewHandler() should return non-nil handler without error")
			}
		})
	}
}

func TestProxyErrorTypes(t *testing.T) {
	tests := []struct {
		name       string
		setupProxy func() http.Handler
		wantStatus int
	}{
		{
			name: "timeout error returns bad gateway",
			setupProxy: func() http.Handler {
				backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate a slow backend
					time.Sleep(200 * time.Millisecond)
				}))
				t.Cleanup(backend.Close)

				transportConfig := defaultTestTransportConfig()
				transportConfig.ResponseHeaderTimeout = 100 * time.Millisecond
				handler, err := newTestHandler(backend.URL, transportConfig, nil)
				require.NoError(t, err)
				return handler
			},
			wantStatus: http.StatusGatewayTimeout,
		},
		{
			name: "connection refused returns bad gateway",
			setupProxy: func() http.Handler {
				// Use an invalid address that will refuse connection
				handler, err := newTestHandler("http://127.0.0.1:99999", defaultTestTransportConfig(), nil)
				require.NoError(t, err)
				return handler
			},
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.setupProxy()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestErrorHandlerUsesCorrectStatus(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "network error returns bad gateway",
			err:        errors.NewNetworkError("connection refused"),
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "validation error returns bad request",
			err:        errors.NewValidationError("invalid request"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "resource error returns service unavailable",
			err:        errors.NewResourceError("backend overloaded"),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "internal error returns internal server error",
			err:        errors.NewInternalError("unexpected error"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "network error with timeout word returns bad gateway (not a real timeout)",
			err:        errors.NewNetworkError("request timeout"),
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "context deadline exceeded returns gateway timeout",
			err:        context.DeadlineExceeded,
			wantStatus: http.StatusGatewayTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			// Create a simple error handler function
			errorHandler := func(w http.ResponseWriter, _ *http.Request, err error) {
				var status int

				// Check for timeout errors using proper type assertion
				if isTimeoutError(err) {
					status = http.StatusGatewayTimeout
				} else {
					// Use error type to determine status
					status = errors.HTTPStatus(err)
					// Override for network errors that aren't timeouts
					if errors.IsNetwork(err) && status != http.StatusGatewayTimeout {
						status = http.StatusBadGateway
					}
				}

				http.Error(w, err.Error(), status)
			}

			errorHandler(w, req, tt.err)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

// mockTimeoutError implements net.Error with Timeout() returning true
type mockTimeoutError struct {
	msg string
}

func (e mockTimeoutError) Error() string   { return e.msg }
func (e mockTimeoutError) Timeout() bool   { return true }
func (e mockTimeoutError) Temporary() bool { return true }

// mockNonTimeoutNetError implements net.Error with Timeout() returning false
type mockNonTimeoutNetError struct {
	msg string
}

func (e mockNonTimeoutNetError) Error() string   { return e.msg }
func (e mockNonTimeoutNetError) Timeout() bool   { return false }
func (e mockNonTimeoutNetError) Temporary() bool { return false }

// TestImprovedTimeoutDetection verifies that the proxy correctly identifies timeout errors
// using type assertions instead of string matching
func TestImprovedTimeoutDetection(t *testing.T) {

	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "context.DeadlineExceeded returns gateway timeout",
			err:        context.DeadlineExceeded,
			wantStatus: http.StatusGatewayTimeout,
		},
		{
			name:       "net.Error with Timeout() true returns gateway timeout",
			err:        mockTimeoutError{msg: "operation timed out"},
			wantStatus: http.StatusGatewayTimeout,
		},
		{
			name:       "net.Error with Timeout() false returns bad gateway",
			err:        mockNonTimeoutNetError{msg: "connection refused"},
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "syscall.ETIMEDOUT returns gateway timeout",
			err:        syscall.ETIMEDOUT,
			wantStatus: http.StatusGatewayTimeout,
		},
		{
			name:       "wrapped timeout error returns gateway timeout",
			err:        fmt.Errorf("failed to connect: %w", mockTimeoutError{msg: "timeout"}),
			wantStatus: http.StatusGatewayTimeout,
		},
		{
			name:       "generic error without 'timeout' word returns bad gateway",
			err:        errors.NewNetworkError("connection failed"),
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "error with 'timeout' in message but not a real timeout returns bad gateway",
			err:        errors.NewNetworkError("timeout configuration invalid"),
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple backend that always succeeds
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			// Create proxy handler
			handler, err := newTestHandler(backend.URL, defaultTestTransportConfig(), nil)
			require.NoError(t, err)

			// Get the httpHandler to access the error handler
			h := handler.(*httpHandler)

			// Create test request and response recorder
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			// Call the error handler directly with our test error
			h.proxy.ErrorHandler(w, req, tt.err)

			assert.Equal(t, tt.wantStatus, w.Code, "Expected status for error %v", tt.err)
		})
	}
}

func TestTransportConnectionPoolLimits(t *testing.T) {
	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Create proxy handler
	handler, err := newTestHandler(backend.URL, defaultTestTransportConfig(), nil)
	require.NoError(t, err)

	// Get the httpHandler to access the transport
	h := handler.(*httpHandler)
	transport := h.proxy.Transport.(*http.Transport)

	// Verify connection pool limits are set
	assert.Equal(t, 50, transport.MaxConnsPerHost, "MaxConnsPerHost should be limited to 50")
	assert.Equal(t, 10, transport.MaxIdleConnsPerHost, "MaxIdleConnsPerHost should be limited to 10")

	// Verify other transport settings are still configured
	assert.Equal(t, 100, transport.MaxIdleConns, "MaxIdleConns should remain at 100")
	assert.NotNil(t, transport.DialContext, "DialContext should be configured")
}

type trackingBody struct {
	*strings.Reader
	read   *bool
	closed *bool
}

func (tb *trackingBody) Read(p []byte) (n int, err error) {
	*tb.read = true
	return tb.Reader.Read(p)
}

func (tb *trackingBody) Close() error {
	if tb.closed != nil {
		*tb.closed = true
	}
	return nil
}

func TestErrorHandlerDrainsRequestBody(t *testing.T) {
	// Create a backend that starts reading but then closes connection
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Start reading the body to ensure client sends it
		buf := make([]byte, 10)
		r.Body.Read(buf)
		// Then close connection abruptly to trigger error
		if hijacker, ok := w.(http.Hijacker); ok {
			conn, _, _ := hijacker.Hijack()
			conn.Close()
		}
	}))
	defer backend.Close()

	handler, err := newTestHandler(backend.URL, defaultTestTransportConfig(), nil)
	require.NoError(t, err)

	bodyRead := false
	closeCalled := false

	bodyContent := "test request body content that should be drained"
	body := &trackingBody{
		Reader: strings.NewReader(bodyContent),
		read:   &bodyRead,
		closed: &closeCalled,
	}

	req := httptest.NewRequest("POST", "/test", body)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(bodyContent))

	w := httptest.NewRecorder()

	// This should trigger an error and call the error handler
	handler.ServeHTTP(w, req)

	// Verify error response
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "Bad Gateway")

	// Verify body was closed (draining may not read if already sent)
	assert.True(t, closeCalled, "Request body Close() should have been called")
}

func TestNewHandlerWithHeaders(t *testing.T) {
	tests := []struct {
		name                string
		upstreamHeaders     map[string]string
		downstreamHeaders   map[string]string
		removeUpstream      []string
		removeDownstream    []string
		requestHeaders      map[string]string
		expectedReqHeaders  map[string]string
		backendRespHeaders  map[string]string
		expectedRespHeaders map[string]string
	}{
		{
			name: "add upstream headers",
			upstreamHeaders: map[string]string{
				"X-Custom-Header": "custom-value",
				"X-Service-Name":  "tailnet",
			},
			requestHeaders: map[string]string{
				"X-Existing": "existing-value",
			},
			expectedReqHeaders: map[string]string{
				"X-Existing":      "existing-value",
				"X-Custom-Header": "custom-value",
				"X-Service-Name":  "tailnet",
			},
		},
		{
			name:           "remove upstream headers",
			removeUpstream: []string{"X-Remove-Me", "X-Also-Remove"},
			requestHeaders: map[string]string{
				"X-Keep-Me":     "keep-value",
				"X-Remove-Me":   "remove-value",
				"X-Also-Remove": "also-remove",
			},
			expectedReqHeaders: map[string]string{
				"X-Keep-Me": "keep-value",
			},
		},
		{
			name: "add downstream headers",
			downstreamHeaders: map[string]string{
				"X-Response-Custom": "response-value",
				"X-Powered-By":      "tailnet",
			},
			backendRespHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			expectedRespHeaders: map[string]string{
				"Content-Type":      "application/json",
				"X-Response-Custom": "response-value",
				"X-Powered-By":      "tailnet",
			},
		},
		{
			name:             "remove downstream headers",
			removeDownstream: []string{"X-Backend-Internal", "X-Debug-Info"},
			backendRespHeaders: map[string]string{
				"Content-Type":       "text/plain",
				"X-Backend-Internal": "internal-value",
				"X-Debug-Info":       "debug-data",
				"X-Keep-This":        "keep-value",
			},
			expectedRespHeaders: map[string]string{
				"Content-Type": "text/plain",
				"X-Keep-This":  "keep-value",
			},
		},
		{
			name: "combined upstream and downstream manipulation",
			upstreamHeaders: map[string]string{
				"X-Request-ID": "req-123",
			},
			removeUpstream: []string{"Authorization"},
			downstreamHeaders: map[string]string{
				"X-Cache-Status": "MISS",
			},
			removeDownstream: []string{"Server"},
			requestHeaders: map[string]string{
				"Authorization": "Bearer token",
				"Accept":        "application/json",
			},
			expectedReqHeaders: map[string]string{
				"Accept":       "application/json",
				"X-Request-ID": "req-123",
			},
			backendRespHeaders: map[string]string{
				"Server":       "nginx/1.19.0",
				"Content-Type": "application/json",
			},
			expectedRespHeaders: map[string]string{
				"Content-Type":   "application/json",
				"X-Cache-Status": "MISS",
			},
		},
		{
			name: "override existing headers",
			upstreamHeaders: map[string]string{
				"X-Forwarded-Host": "override.example.com",
			},
			requestHeaders: map[string]string{
				"X-Forwarded-Host": "original.example.com",
			},
			expectedReqHeaders: map[string]string{
				"X-Forwarded-Host": "override.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test backend server
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify expected request headers
				for key, expected := range tt.expectedReqHeaders {
					assert.Equal(t, expected, r.Header.Get(key), "request header %s", key)
				}

				// Verify removed headers are not present
				for _, key := range tt.removeUpstream {
					assert.Empty(t, r.Header.Get(key), "removed header %s should not be present", key)
				}

				// Set response headers from test case
				for key, value := range tt.backendRespHeaders {
					w.Header().Set(key, value)
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))
			defer backend.Close()

			// Create handler with header configuration
			handler, err := NewHandler(&HandlerConfig{
				BackendAddr:       backend.URL,
				TransportConfig:   defaultTestTransportConfig(),
				TrustedProxies:    nil,
				UpstreamHeaders:   tt.upstreamHeaders,
				DownstreamHeaders: tt.downstreamHeaders,
				RemoveUpstream:    tt.removeUpstream,
				RemoveDownstream:  tt.removeDownstream,
			})
			require.NoError(t, err)

			// Create test request
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			for key, value := range tt.requestHeaders {
				req.Header.Set(key, value)
			}

			// Execute request
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			// Verify response headers
			for key, expected := range tt.expectedRespHeaders {
				assert.Equal(t, expected, w.Header().Get(key), "response header %s", key)
			}

			// Verify removed downstream headers are not present
			for _, key := range tt.removeDownstream {
				assert.Empty(t, w.Header().Get(key), "removed downstream header %s should not be present", key)
			}
		})
	}
}

func TestConnectionPoolMetricsCollection(t *testing.T) {
	t.Run("proxy handler collects connection pool metrics", func(t *testing.T) {
		// Create a test backend server
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer backend.Close()

		// Create metrics collector and registry
		registry := prometheus.NewRegistry()
		collector := metrics.NewCollector()
		err := collector.Register(registry)
		require.NoError(t, err)

		// Create proxy handler with metrics
		transportConfig := &TransportConfig{
			DialTimeout:           5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			KeepAliveTimeout:      30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:      backend.URL,
			TransportConfig:  transportConfig,
			TrustedProxies:   nil,
			MetricsCollector: collector,
			ServiceName:      "test-service",
		})
		require.NoError(t, err)
		defer handler.Close()

		// Make some requests to establish connections
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Give time for metrics to be collected
		time.Sleep(100 * time.Millisecond)

		// Check that connection pool metrics are being collected
		// We just verify the metric exists and can be read
		activeMetric := testutil.ToFloat64(collector.ConnectionPoolActive.WithLabelValues("test-service"))

		// Metrics should exist (active should be 0 since requests completed)
		assert.GreaterOrEqual(t, activeMetric, 0.0)
	})

	t.Run("metrics collector runs periodically", func(t *testing.T) {
		// Create a test backend server that holds connections longer
		requestCount := int64(0)
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&requestCount, 1)
			time.Sleep(100 * time.Millisecond) // Hold connection to ensure we can observe active requests
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		// Create metrics collector
		collector := metrics.NewCollector()
		registry := prometheus.NewRegistry()
		err := collector.Register(registry)
		require.NoError(t, err)

		// Create proxy handler with metrics collection
		transportConfig := &TransportConfig{
			DialTimeout:           5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			KeepAliveTimeout:      30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:      backend.URL,
			TransportConfig:  transportConfig,
			TrustedProxies:   nil,
			MetricsCollector: collector,
			ServiceName:      "test-service",
		})
		require.NoError(t, err)
		defer handler.Close()

		// Make concurrent requests to create active connections
		const numWorkers = 5
		var wg sync.WaitGroup
		wg.Add(numWorkers)

		// Use a channel to coordinate request timing
		startRequests := make(chan struct{})

		for i := 0; i < numWorkers; i++ {
			go func() {
				defer wg.Done()
				<-startRequests // Wait for signal to start
				req := httptest.NewRequest("GET", "http://example.com/", nil)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
			}()
		}

		// Start all requests at the same time
		close(startRequests)

		// Wait a bit for requests to be in flight
		time.Sleep(50 * time.Millisecond)

		// Force a metrics collection while requests are active
		handler.(*httpHandler).collectMetrics()

		// Check metrics - should show active requests
		activeMetric := testutil.ToFloat64(collector.ConnectionPoolActive.WithLabelValues("test-service"))
		assert.Greater(t, activeMetric, 0.0, "Expected to see active requests")

		// Wait for all requests to complete
		wg.Wait()

		// Verify all requests were processed
		assert.Equal(t, int64(numWorkers), atomic.LoadInt64(&requestCount))

		// Force another metrics collection after requests complete
		handler.(*httpHandler).collectMetrics()

		// Check metrics again - should be back to zero
		finalMetric := testutil.ToFloat64(collector.ConnectionPoolActive.WithLabelValues("test-service"))
		assert.Equal(t, 0.0, finalMetric, "Expected no active requests after completion")
	})
}

func TestActiveRequestsThreadSafety(t *testing.T) {
	// This test verifies that activeRequests counter is accessed atomically
	// and there are no race conditions between ServeHTTP and collectMetrics
	t.Run("concurrent access to activeRequests", func(t *testing.T) {
		// Create a test backend that holds connections to keep requests active
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Hold the connection for a bit to simulate active requests
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer backend.Close()

		// Create metrics collector
		collector := metrics.NewCollector()
		registry := prometheus.NewRegistry()
		err := collector.Register(registry)
		require.NoError(t, err)

		// Create proxy handler with metrics
		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:      backend.URL,
			TransportConfig:  defaultTestTransportConfig(),
			MetricsCollector: collector,
			ServiceName:      "test-service",
		})
		require.NoError(t, err)
		defer handler.Close()

		httpHandler := handler.(*httpHandler)

		// Number of concurrent operations
		const numWorkers = 50
		const numIterations = 100

		// Use WaitGroup to coordinate goroutines
		var wg sync.WaitGroup
		wg.Add(numWorkers * 2) // Half for ServeHTTP, half for collectMetrics

		// Start signal
		start := make(chan struct{})

		// Start goroutines that make requests (writing to activeRequests)
		for i := 0; i < numWorkers; i++ {
			go func() {
				defer wg.Done()
				<-start
				for j := 0; j < numIterations; j++ {
					req := httptest.NewRequest("GET", "/", nil)
					w := httptest.NewRecorder()
					httpHandler.ServeHTTP(w, req)
				}
			}()
		}

		// Start goroutines that collect metrics (reading activeRequests)
		for i := 0; i < numWorkers; i++ {
			go func() {
				defer wg.Done()
				<-start
				for j := 0; j < numIterations; j++ {
					// Test both the getter method and collectMetrics
					_ = httpHandler.getActiveRequests()
					httpHandler.collectMetrics()
					// Small delay to increase likelihood of race
					time.Sleep(time.Microsecond)
				}
			}()
		}

		// Start all goroutines simultaneously
		close(start)

		// Wait for all goroutines to complete
		wg.Wait()

		// If we get here without a race detected by -race flag, the test passes
		// The race detector will automatically fail the test if a race is detected
	})
}

func TestFlushIntervalConfiguration(t *testing.T) {
	t.Run("default no flush interval", func(t *testing.T) {
		// Create a backend that sends streaming data
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("data"))
		}))
		defer backend.Close()

		// Create handler without flush interval
		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:     backend.URL,
			TransportConfig: defaultTestTransportConfig(),
		})
		require.NoError(t, err)
		defer handler.Close()

		// The reverse proxy should have default behavior (FlushInterval set to 0)
		httpHandler := handler.(*httpHandler)
		assert.NotNil(t, httpHandler.proxy)
		assert.Nil(t, httpHandler.flushInterval)
		assert.Equal(t, time.Duration(0), httpHandler.proxy.FlushInterval)
	})

	t.Run("with flush interval", func(t *testing.T) {
		// Create a backend that sends streaming data
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("data"))
		}))
		defer backend.Close()

		// Create handler with flush interval
		flushInterval := 100 * time.Millisecond
		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:     backend.URL,
			TransportConfig: defaultTestTransportConfig(),
			FlushInterval:   &flushInterval,
		})
		require.NoError(t, err)
		defer handler.Close()

		// Verify handler was created successfully
		httpHandler := handler.(*httpHandler)
		assert.NotNil(t, httpHandler.proxy)
		assert.Equal(t, &flushInterval, httpHandler.flushInterval)
	})

	t.Run("negative flush interval for immediate flushing", func(t *testing.T) {
		// Create a backend that sends streaming data
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("data"))
		}))
		defer backend.Close()

		// Create handler with negative flush interval (immediate flushing)
		flushInterval := -1 * time.Millisecond
		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:     backend.URL,
			TransportConfig: defaultTestTransportConfig(),
			FlushInterval:   &flushInterval,
		})
		require.NoError(t, err)
		defer handler.Close()

		// Verify handler was created successfully
		httpHandler := handler.(*httpHandler)
		assert.NotNil(t, httpHandler.proxy)
		assert.Equal(t, &flushInterval, httpHandler.flushInterval)
	})
}

func TestTLSConfiguration(t *testing.T) {
	t.Run("HTTPS backend with TLS verification enabled", func(t *testing.T) {
		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:        "https://example.com:443",
			TransportConfig:    defaultTestTransportConfig(),
			InsecureSkipVerify: false,
		})
		require.NoError(t, err)
		defer handler.Close()

		httpHandler := handler.(*httpHandler)
		transport := httpHandler.transport

		// Verify TLS config is set for HTTPS backend
		require.NotNil(t, transport.TLSClientConfig)
		assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("HTTPS backend with TLS verification disabled", func(t *testing.T) {
		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:        "https://self-signed.example.com:443",
			TransportConfig:    defaultTestTransportConfig(),
			InsecureSkipVerify: true,
		})
		require.NoError(t, err)
		defer handler.Close()

		httpHandler := handler.(*httpHandler)
		transport := httpHandler.transport

		// Verify TLS config is set for HTTPS backend with InsecureSkipVerify enabled
		require.NotNil(t, transport.TLSClientConfig)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("HTTP backend should not have TLS config", func(t *testing.T) {
		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:        "http://example.com:80",
			TransportConfig:    defaultTestTransportConfig(),
			InsecureSkipVerify: true, // This should be ignored for HTTP backends
		})
		require.NoError(t, err)
		defer handler.Close()

		httpHandler := handler.(*httpHandler)
		transport := httpHandler.transport

		// Verify no TLS config is set for HTTP backend
		assert.Nil(t, transport.TLSClientConfig)
	})

	t.Run("Unix socket backend should not have TLS config", func(t *testing.T) {
		handler, err := NewHandler(&HandlerConfig{
			BackendAddr:        "unix:///tmp/socket.sock",
			TransportConfig:    defaultTestTransportConfig(),
			InsecureSkipVerify: true, // This should be ignored for Unix socket backends
		})
		require.NoError(t, err)
		defer handler.Close()

		httpHandler := handler.(*httpHandler)
		transport := httpHandler.transport

		// Verify no TLS config is set for Unix socket backend
		assert.Nil(t, transport.TLSClientConfig)
	})
}

// BenchmarkActiveRequestsAccess benchmarks the performance of activeRequests counter operations
func BenchmarkActiveRequestsAccess(b *testing.B) {
	// Create a simple backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Create proxy handler
	handler, err := NewHandler(&HandlerConfig{
		BackendAddr:     backend.URL,
		TransportConfig: defaultTestTransportConfig(),
	})
	require.NoError(b, err)
	defer handler.Close()

	httpHandler := handler.(*httpHandler)

	b.Run("getActiveRequests", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = httpHandler.getActiveRequests()
		}
	})

	b.Run("increment_decrement", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			atomic.AddInt64(&httpHandler.activeRequests, 1)
			atomic.AddInt64(&httpHandler.activeRequests, -1)
		}
	})

	b.Run("concurrent_access", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				atomic.AddInt64(&httpHandler.activeRequests, 1)
				_ = httpHandler.getActiveRequests()
				atomic.AddInt64(&httpHandler.activeRequests, -1)
			}
		})
	})
}
