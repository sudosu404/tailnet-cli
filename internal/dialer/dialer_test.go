package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	tferrors "github.com/jtdowney/tsbridge/internal/errors"
)

func TestDialBackend(t *testing.T) {
	tests := []struct {
		name          string
		addr          string
		maxRetries    int
		retryDelay    time.Duration
		mockDialer    func(failCount int) func(ctx context.Context, network, addr string) (net.Conn, error)
		expectedError bool
		expectedDials int
	}{
		{
			name:       "succeeds on first try",
			addr:       "tcp://localhost:8080",
			maxRetries: 3,
			retryDelay: 10 * time.Millisecond,
			mockDialer: func(failCount int) func(ctx context.Context, network, addr string) (net.Conn, error) {
				var dials int
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					dials++
					if dials <= failCount {
						return nil, errors.New("connection refused")
					}
					return &mockConn{}, nil
				}
			},
			expectedError: false,
			expectedDials: 1,
		},
		{
			name:       "succeeds after retries",
			addr:       "tcp://localhost:8080",
			maxRetries: 3,
			retryDelay: 10 * time.Millisecond,
			mockDialer: func(failCount int) func(ctx context.Context, network, addr string) (net.Conn, error) {
				var dials int
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					dials++
					if dials <= failCount {
						return nil, errors.New("connection refused")
					}
					return &mockConn{}, nil
				}
			},
			expectedError: false,
			expectedDials: 3,
		},
		{
			name:       "fails after max retries",
			addr:       "tcp://localhost:8080",
			maxRetries: 3,
			retryDelay: 10 * time.Millisecond,
			mockDialer: func(failCount int) func(ctx context.Context, network, addr string) (net.Conn, error) {
				var dials int
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					dials++
					return nil, errors.New("connection refused")
				}
			},
			expectedError: true,
			expectedDials: 4, // initial + 3 retries
		},
		{
			name:       "unix socket",
			addr:       "unix:///var/run/app.sock",
			maxRetries: 1,
			retryDelay: 10 * time.Millisecond,
			mockDialer: func(failCount int) func(ctx context.Context, network, addr string) (net.Conn, error) {
				var dials int
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					dials++
					if network != "unix" {
						t.Errorf("expected network 'unix', got %q", network)
					}
					if addr != "/var/run/app.sock" {
						t.Errorf("expected addr '/var/run/app.sock', got %q", addr)
					}
					return &mockConn{}, nil
				}
			},
			expectedError: false,
			expectedDials: 1,
		},
		{
			name:          "invalid address",
			addr:          "invalid://address",
			maxRetries:    1,
			retryDelay:    10 * time.Millisecond,
			mockDialer:    nil, // shouldn't be called
			expectedError: true,
			expectedDials: 0,
		},
		{
			name:       "respects context cancellation",
			addr:       "tcp://localhost:8080",
			maxRetries: 10,
			retryDelay: 1 * time.Second,
			mockDialer: func(failCount int) func(ctx context.Context, network, addr string) (net.Conn, error) {
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					default:
						return nil, errors.New("connection refused")
					}
				}
			},
			expectedError: true,
			expectedDials: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dialCount int
			var dialer Dialer
			if tt.mockDialer != nil {
				failCount := 0
				if tt.expectedDials > 1 {
					failCount = tt.expectedDials - 1
				}
				mockFn := tt.mockDialer(failCount)
				dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialCount++
					return mockFn(ctx, network, addr)
				}
			}

			ctx := context.Background()
			if tt.name == "respects context cancellation" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}

			conn, err := DialBackend(ctx, tt.addr, tt.maxRetries, tt.retryDelay, dialer)

			if tt.expectedError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.expectedError && conn == nil {
				t.Error("expected connection, got nil")
			}
			if tt.expectedError && conn != nil {
				t.Error("expected nil connection, got non-nil")
			}

			if tt.mockDialer != nil && dialCount != tt.expectedDials {
				t.Errorf("expected %d dials, got %d", tt.expectedDials, dialCount)
			}
		})
	}
}

func TestParseBackendAddress(t *testing.T) {
	tests := []struct {
		name            string
		addr            string
		expectedNetwork string
		expectedAddr    string
		expectedError   bool
	}{
		{
			name:            "tcp with port",
			addr:            "tcp://localhost:8080",
			expectedNetwork: "tcp",
			expectedAddr:    "localhost:8080",
			expectedError:   false,
		},
		{
			name:            "tcp IP with port",
			addr:            "tcp://192.168.1.1:8080",
			expectedNetwork: "tcp",
			expectedAddr:    "192.168.1.1:8080",
			expectedError:   false,
		},
		{
			name:            "unix socket",
			addr:            "unix:///var/run/app.sock",
			expectedNetwork: "unix",
			expectedAddr:    "/var/run/app.sock",
			expectedError:   false,
		},
		{
			name:            "localhost shorthand",
			addr:            "localhost:8080",
			expectedNetwork: "tcp",
			expectedAddr:    "localhost:8080",
			expectedError:   false,
		},
		{
			name:            "IP shorthand",
			addr:            "192.168.1.1:8080",
			expectedNetwork: "tcp",
			expectedAddr:    "192.168.1.1:8080",
			expectedError:   false,
		},
		{
			name:          "invalid scheme",
			addr:          "http://localhost:8080",
			expectedError: true,
		},
		{
			name:          "empty address",
			addr:          "",
			expectedError: true,
		},
		{
			name:          "tcp without port",
			addr:          "tcp://localhost",
			expectedError: true,
		},
		{
			name:          "unix without path",
			addr:          "unix://",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, addr, err := ParseBackendAddress(tt.addr)

			if tt.expectedError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.expectedError {
				if network != tt.expectedNetwork {
					t.Errorf("expected network %q, got %q", tt.expectedNetwork, network)
				}
				if addr != tt.expectedAddr {
					t.Errorf("expected addr %q, got %q", tt.expectedAddr, addr)
				}
			}
		})
	}
}

func TestDialBackendErrorTypes(t *testing.T) {
	tests := []struct {
		name        string
		backendAddr string
		wantErrType bool
		checkFunc   func(error) bool
	}{
		{
			name:        "invalid backend address returns network error",
			backendAddr: "invalid-address",
			wantErrType: true,
			checkFunc:   tferrors.IsNetwork,
		},
		{
			name:        "connection refused returns network error",
			backendAddr: "127.0.0.1:99999", // Invalid port
			wantErrType: true,
			checkFunc:   tferrors.IsNetwork,
		},
		{
			name:        "timeout returns network error",
			backendAddr: "198.51.100.1:80", // TEST-NET-2 address that won't respond
			wantErrType: true,
			checkFunc:   tferrors.IsNetwork,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			_, err := DialBackend(ctx, tt.backendAddr, 0, 0, nil)
			if err == nil {
				t.Fatal("expected error but got none")
			}

			if got := tt.checkFunc(err); got != tt.wantErrType {
				t.Errorf("error type check = %v, want %v, error: %v", got, tt.wantErrType, err)
			}
		})
	}
}

func TestDialBackendWithRetry(t *testing.T) {
	ctx := context.Background()

	// Use an address that will fail
	_, err := DialBackend(ctx, "127.0.0.1:99999", 3, 10*time.Millisecond, nil)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	// Check that it's a network error
	if !tferrors.IsNetwork(err) {
		t.Errorf("expected network error, got %v", err)
	}

	// Check retry information
	if !tferrors.IsRetryable(err) {
		t.Error("expected error to be marked as retryable")
	}

	attempt, maxAttempts, ok := tferrors.GetRetryInfo(err)
	if !ok {
		t.Error("expected to extract retry info")
	}
	if attempt != 4 {
		t.Errorf("expected attempt = 4, got %d", attempt)
	}
	if maxAttempts != 4 {
		t.Errorf("expected maxAttempts = 4, got %d", maxAttempts)
	}
}

// mockConn implements net.Conn for testing
type mockConn struct {
	net.Conn
}

func (m *mockConn) Close() error {
	return nil
}
