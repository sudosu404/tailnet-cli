// Package dialer provides backend connection dialing functionality.
package dialer

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jtdowney/tsbridge/internal/errors"
)

// Dialer is a function that dials a network connection
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// DialBackend dials a backend address with retry logic
func DialBackend(ctx context.Context, addr string, maxRetries int, retryDelay time.Duration, dialer Dialer) (net.Conn, error) {
	network, address, err := ParseBackendAddress(addr)
	if err != nil {
		return nil, errors.WrapNetwork(err, "parse backend address")
	}

	if dialer == nil {
		d := &net.Dialer{}
		dialer = d.DialContext
	}

	var lastErr error
	attempts := maxRetries + 1 // initial attempt + retries

	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, errors.WrapNetwork(ctx.Err(), "context cancelled during retry delay")
			case <-time.After(retryDelay):
			}
		}

		conn, err := dialer(ctx, network, address)
		if err == nil {
			return conn, nil
		}

		lastErr = err

		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return nil, errors.WrapNetwork(ctx.Err(), "context cancelled during dial")
		default:
		}
	}

	// Wrap the final error as a network error with retry information
	networkErr := errors.WrapNetwork(lastErr, fmt.Sprintf("failed after %d attempts", attempts))
	return nil, errors.WithRetry(networkErr, attempts, attempts)
}

// ParseBackendAddress parses a backend address into network and address components
func ParseBackendAddress(addr string) (network, address string, err error) {
	if addr == "" {
		return "", "", fmt.Errorf("empty address")
	}

	// Handle unix:// scheme
	if strings.HasPrefix(addr, "unix://") {
		path := strings.TrimPrefix(addr, "unix://")
		if path == "" {
			return "", "", fmt.Errorf("empty unix socket path")
		}
		return "unix", path, nil
	}

	// Handle tcp:// scheme
	if strings.HasPrefix(addr, "tcp://") {
		hostPort := strings.TrimPrefix(addr, "tcp://")
		if hostPort == "" {
			return "", "", fmt.Errorf("empty tcp address")
		}
		if !strings.Contains(hostPort, ":") {
			return "", "", fmt.Errorf("tcp address missing port")
		}
		return "tcp", hostPort, nil
	}

	// Check for other schemes that we don't support
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return "", "", fmt.Errorf("parse URL: %w", err)
		}
		return "", "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	// Default to TCP for addresses without scheme
	if strings.Contains(addr, ":") {
		return "tcp", addr, nil
	}

	return "", "", fmt.Errorf("invalid address format: %s", addr)
}
