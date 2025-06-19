// Package middleware implements HTTP middleware for request processing.
package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"log/slog"
	"tailscale.com/client/tailscale/apitype"
)

// WhoisClient is an interface for performing Tailscale WhoIs lookups
type WhoisClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// Whois returns a middleware that performs Tailscale identity lookups
// and adds headers with user information when enabled
func Whois(client WhoisClient, enabled bool, timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If whois is disabled, skip to next handler
			if !enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Perform lookup and add headers
			performWhoisLookup(client, timeout, r)

			// Continue to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// performWhoisLookup performs the whois lookup and adds headers to the request
func performWhoisLookup(client WhoisClient, timeout time.Duration, r *http.Request) {
	// Create context with timeout for whois lookup
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	// Perform whois lookup
	resp, err := client.WhoIs(ctx, r.RemoteAddr)
	if err != nil {
		logWhoisError(err, r.RemoteAddr, timeout)
		return
	}

	// Add headers if we got a response
	if resp != nil {
		addUserHeaders(r, resp)
		addAddressHeaders(r, resp)
	}
}

// logWhoisError logs the appropriate error message based on the error type
func logWhoisError(err error, remoteAddr string, timeout time.Duration) {
	if err == context.DeadlineExceeded {
		slog.Warn("whois lookup timed out", "remote_addr", remoteAddr, "timeout", timeout)
	} else {
		slog.Warn("whois lookup failed", "remote_addr", remoteAddr, "error", err)
	}
}

// addUserHeaders adds user-related headers from the whois response
func addUserHeaders(r *http.Request, resp *apitype.WhoIsResponse) {
	if resp.UserProfile == nil {
		return
	}

	if resp.UserProfile.LoginName != "" {
		r.Header.Set("X-Tailscale-User", resp.UserProfile.LoginName)
		r.Header.Set("X-Tailscale-Login", resp.UserProfile.LoginName)
	}
	if resp.UserProfile.DisplayName != "" {
		r.Header.Set("X-Tailscale-Name", resp.UserProfile.DisplayName)
	}
}

// addAddressHeaders adds address-related headers from the whois response
func addAddressHeaders(r *http.Request, resp *apitype.WhoIsResponse) {
	if resp.Node == nil || len(resp.Node.Addresses) == 0 {
		return
	}

	// Convert prefixes to IP addresses and join with comma
	var addresses []string
	for _, prefix := range resp.Node.Addresses {
		addresses = append(addresses, prefix.Addr().String())
	}
	r.Header.Set("X-Tailscale-Addresses", strings.Join(addresses, ","))
}
