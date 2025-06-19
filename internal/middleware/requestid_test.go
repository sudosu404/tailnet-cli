package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/jtdowney/tsbridge/internal/testutil"
)

func TestRequestID(t *testing.T) {
	tests := []struct {
		name              string
		incomingRequestID string
		wantGenerated     bool
	}{
		{
			name:              "generates new request ID when none provided",
			incomingRequestID: "",
			wantGenerated:     true,
		},
		{
			name:              "uses existing request ID from header",
			incomingRequestID: "existing-request-id-123",
			wantGenerated:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedRequestID string
			var capturedContext context.Context

			// Create a test handler that captures the request ID
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedContext = r.Context()
				capturedRequestID = GetRequestID(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with RequestID middleware
			wrapped := RequestID(handler)

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.incomingRequestID != "" {
				req.Header.Set("X-Request-ID", tt.incomingRequestID)
			}

			// Execute request
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			// Verify request ID was captured
			if capturedRequestID == "" {
				t.Fatal("expected non-empty request ID")
			}

			if tt.wantGenerated {
				// Verify a new ID was generated (UUID format)
				uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
				if !uuidRegex.MatchString(capturedRequestID) {
					t.Errorf("expected UUID format, got %s", capturedRequestID)
				}
			} else {
				// Verify existing ID was used
				testutil.AssertEqual(t, tt.incomingRequestID, capturedRequestID)
			}

			// Verify request ID is in context
			testutil.AssertEqual(t, capturedRequestID, GetRequestID(capturedContext))

			// Verify response header contains request ID
			testutil.AssertEqual(t, capturedRequestID, rr.Header().Get("X-Request-ID"))
		})
	}
}

func TestRequestIDPropagation(t *testing.T) {
	// Test that request ID is propagated to backend requests
	var backendRequestID string

	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequestID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Create a proxy handler that forwards to backend
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate proxy behavior - forward request with headers
		backendReq, err := http.NewRequestWithContext(r.Context(), "GET", backend.URL, nil)
		testutil.RequireNoError(t, err)

		// Copy request ID to backend request
		if requestID := GetRequestID(r.Context()); requestID != "" {
			backendReq.Header.Set("X-Request-ID", requestID)
		}

		resp, err := http.DefaultClient.Do(backendReq)
		testutil.RequireNoError(t, err)
		defer resp.Body.Close()

		w.WriteHeader(resp.StatusCode)
	})

	// Wrap with RequestID middleware
	wrapped := RequestID(proxyHandler)

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "test-request-123")

	// Execute request
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	// Verify request ID was propagated to backend
	testutil.AssertEqual(t, "test-request-123", backendRequestID)
}

func TestGetRequestIDFromEmptyContext(t *testing.T) {
	// Test GetRequestID with context that doesn't have request ID
	ctx := context.Background()
	requestID := GetRequestID(ctx)
	testutil.AssertEqual(t, "", requestID)
}
