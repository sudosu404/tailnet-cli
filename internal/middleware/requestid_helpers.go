package middleware

import (
	"context"
	"log/slog"
)

// LogWithRequestID returns a logger that includes the request ID from the context
func LogWithRequestID(ctx context.Context) *slog.Logger {
	requestID := GetRequestID(ctx)
	if requestID == "" {
		return slog.Default()
	}
	return slog.With("request_id", requestID)
}
