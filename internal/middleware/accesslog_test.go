package middleware

import (
	"bytes"
	"fmt"
	"github.com/jtdowney/tsbridge/internal/testutil"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLog(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		requestID      string
		responseStatus int
		responseSize   int
		userAgent      string
		wantLogged     bool
		checkFields    map[string]interface{}
	}{
		{
			name:           "logs successful request",
			method:         "GET",
			path:           "/api/test",
			requestID:      "test-123",
			responseStatus: http.StatusOK,
			responseSize:   100,
			userAgent:      "test-agent/1.0",
			wantLogged:     true,
			checkFields: map[string]interface{}{
				"method":     "GET",
				"path":       "/api/test",
				"status":     200,
				"size":       100,
				"request_id": "test-123",
				"user_agent": "test-agent/1.0",
			},
		},
		{
			name:           "logs error request",
			method:         "POST",
			path:           "/api/error",
			requestID:      "error-456",
			responseStatus: http.StatusInternalServerError,
			responseSize:   50,
			wantLogged:     true,
			checkFields: map[string]interface{}{
				"method":     "POST",
				"path":       "/api/error",
				"status":     500,
				"size":       50,
				"request_id": "error-456",
			},
		},
		{
			name:           "logs request without request ID",
			method:         "GET",
			path:           "/health",
			requestID:      "",
			responseStatus: http.StatusOK,
			responseSize:   10,
			wantLogged:     true,
			checkFields: map[string]interface{}{
				"method": "GET",
				"path":   "/health",
				"status": 200,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))

			// Create test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseStatus)
				if tt.responseSize > 0 {
					w.Write(make([]byte, tt.responseSize))
				}
			})

			// Wrap with access log middleware
			wrapped := AccessLog(logger, "test-service")(handler)

			// Create request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.requestID != "" {
				req.Header.Set("X-Request-ID", tt.requestID)
			}
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			// Execute request
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			// Check response
			testutil.AssertEqual(t, tt.responseStatus, rr.Code)

			// Check logs
			logOutput := buf.String()
			if tt.wantLogged {
				testutil.AssertNotEmpty(t, logOutput)

				// Verify log contains expected fields
				for field, value := range tt.checkFields {
					if field == "request_id" && value == "" {
						// Should not contain request_id field if empty
						testutil.AssertNotContains(t, logOutput, `"request_id"`)
					} else {
						testutil.AssertContains(t, logOutput, field)
						// Convert value to string for comparison
						switch v := value.(type) {
						case string:
							testutil.AssertContains(t, logOutput, v)
						case int:
							testutil.AssertContains(t, logOutput, strings.TrimSpace(fmt.Sprintf("%d", v)))
						}
					}
				}

				// Should always contain duration
				testutil.AssertContains(t, logOutput, "duration_ms")
				testutil.AssertContains(t, logOutput, "service")
				testutil.AssertContains(t, logOutput, "test-service")
			} else {
				testutil.AssertEqual(t, "", logOutput)
			}
		})
	}
}

func TestAccessLogWithRequestIDFromContext(t *testing.T) {
	// Test that access log can get request ID from context (set by RequestID middleware)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Chain RequestID -> AccessLog -> Handler
	chain := RequestID(AccessLog(logger, "test-service")(handler))

	// Request without X-Request-ID header (will be generated)
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	chain.ServeHTTP(rr, req)

	// Check that log contains the generated request ID
	logOutput := buf.String()
	testutil.AssertContains(t, logOutput, "request_id")
	// Should contain a UUID pattern
	testutil.AssertRegexp(t, `"request_id":"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"`, logOutput)
}

func TestAccessLogResponseWriter(t *testing.T) {
	// Test the response writer wrapper tracks size correctly
	rw := &accessLogResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
	}

	// Write some data
	data := []byte("Hello, World!")
	n, err := rw.Write(data)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, len(data), n)
	testutil.AssertEqual(t, len(data), rw.size)

	// Write more data
	moreData := []byte(" More data")
	n, err = rw.Write(moreData)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, len(moreData), n)
	testutil.AssertEqual(t, len(data)+len(moreData), rw.size)

	// Test WriteHeader
	rw.WriteHeader(http.StatusNotFound)
	testutil.AssertEqual(t, http.StatusNotFound, rw.statusCode)
}
