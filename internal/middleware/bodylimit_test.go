package middleware

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxBytesHandler(t *testing.T) {
	tests := []struct {
		name           string
		maxBytes       int64
		body           string
		contentLength  string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "request within limit",
			maxBytes:       10,
			body:           "hello",
			expectedStatus: http.StatusOK,
			expectedBody:   "hello",
		},
		{
			name:           "request at limit",
			maxBytes:       5,
			body:           "hello",
			expectedStatus: http.StatusOK,
			expectedBody:   "hello",
		},
		{
			name:           "request exceeds limit",
			maxBytes:       5,
			body:           "hello world",
			expectedStatus: http.StatusRequestEntityTooLarge,
			expectedBody:   "Request body too large\n",
		},
		{
			name:           "content-length exceeds limit",
			maxBytes:       5,
			body:           "hello world", // actual body that exceeds limit
			contentLength:  "100",
			expectedStatus: http.StatusRequestEntityTooLarge,
			expectedBody:   "Request body too large\n",
		},
		{
			name:           "negative limit (no limit)",
			maxBytes:       -1,
			body:           strings.Repeat("x", 1000),
			expectedStatus: http.StatusOK,
			expectedBody:   strings.Repeat("x", 1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Write(body)
			})

			wrapped := MaxBytesHandler(tt.maxBytes)(handler)

			req := httptest.NewRequest("POST", "/", strings.NewReader(tt.body))
			if tt.contentLength != "" {
				req.Header.Set("Content-Length", tt.contentLength)
			}

			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, tt.expectedBody, rec.Body.String())
		})
	}
}

// mockHijacker is a test implementation of http.ResponseWriter that supports hijacking
type mockHijacker struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.hijacked = true
	// Return a mock connection
	server, client := net.Pipe()
	// Close server side immediately for test
	server.Close()
	return client, bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client)), nil
}

func TestMaxBytesHandlerHijacking(t *testing.T) {
	// Test that hijacking still works through our wrapper
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		require.True(t, ok, "ResponseWriter should implement Hijacker")

		conn, _, err := hijacker.Hijack()
		require.NoError(t, err)
		conn.Close()
	})

	wrapped := MaxBytesHandler(1024)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	// Use our mock hijacker
	rec := &mockHijacker{ResponseRecorder: httptest.NewRecorder()}
	wrapped.ServeHTTP(rec, req)

	assert.True(t, rec.hijacked, "Handler should have hijacked the connection")
}

func TestMaxBytesHandlerNoHijackSupport(t *testing.T) {
	// Test when underlying ResponseWriter doesn't support hijacking
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		require.True(t, ok, "ResponseWriter should implement Hijacker")

		_, _, err := hijacker.Hijack()
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not support hijacking")

		// Write normal response when hijacking fails
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("hijacking not supported"))
	})

	wrapped := MaxBytesHandler(1024)(handler)

	req := httptest.NewRequest("GET", "/", nil)

	// Regular ResponseRecorder doesn't support hijacking
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "hijacking not supported", rec.Body.String())
}

func TestMaxBytesHandlerLargeBodyPartialRead(t *testing.T) {
	// Test that MaxBytesReader properly limits body reading
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read more than the limit
		buf := make([]byte, 20)
		n, err := r.Body.Read(buf)

		// Should read up to the limit and then get an error
		if err != nil && err != io.EOF {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}

		w.Write(buf[:n])
	})

	wrapped := MaxBytesHandler(10)(handler)

	req := httptest.NewRequest("POST", "/", strings.NewReader("this is a very long body"))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// The handler should have received the error from MaxBytesReader
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}
