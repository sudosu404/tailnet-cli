package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/jtdowney/tsbridge/internal/config"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// Test that signal handling is simple and clean
func TestSignalHandlingSimplicity(t *testing.T) {
	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal channel
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Simulate signal handling logic that should be in main
	signalHandled := make(chan struct{})
	go func() {
		select {
		case <-sigCh:
			// On signal, just cancel the context
			cancel()
			close(signalHandled)
		case <-ctx.Done():
			// Context cancelled by other means
			return
		}
	}()

	// Send a signal
	sigCh <- os.Interrupt

	// Verify signal was handled
	select {
	case <-signalHandled:
		// Good, signal was handled
	case <-time.After(1 * time.Second):
		t.Fatal("Signal was not handled within timeout")
	}

	// Verify context was cancelled
	select {
	case <-ctx.Done():
		assert.Equal(t, context.Canceled, ctx.Err())
	default:
		t.Fatal("Context was not cancelled after signal")
	}
}

// TestExitFuncAllowsDeferExecution verifies that using exitFunc allows defer statements to run
func TestExitFuncAllowsDeferExecution(t *testing.T) {
	// Save original exitFunc
	oldExitFunc := exitFunc
	defer func() {
		exitFunc = oldExitFunc
	}()

	// Track exit calls
	exitCalled := false
	exitCode := -1
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
		// Don't actually exit in tests
	}

	// Capture log output
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	// Test a function that uses exitFunc
	deferExecuted := false
	func() {
		defer func() {
			deferExecuted = true
		}()
		slog.Error("test error")
		exitFunc(1)
	}()

	// Verify behavior
	assert.True(t, exitCalled, "exitFunc should have been called")
	assert.Equal(t, 1, exitCode)
	assert.True(t, deferExecuted, "defer should have been executed")
	assert.Contains(t, logBuf.String(), "test error")
}

// TestExitFuncInSignalHandler verifies exitFunc works in goroutines too
func TestExitFuncInSignalHandler(t *testing.T) {
	// Save original exitFunc
	oldExitFunc := exitFunc
	defer func() {
		exitFunc = oldExitFunc
	}()

	// Track exit
	exitChan := make(chan int, 1)
	exitFunc = func(code int) {
		exitChan <- code
	}

	// Capture logs
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	// Simulate signal handler error path
	go func() {
		slog.Error("shutdown error", "error", fmt.Errorf("test error"))
		exitFunc(1)
	}()

	// Wait for exit
	select {
	case code := <-exitChan:
		assert.Equal(t, 1, code)
		assert.Contains(t, logBuf.String(), "shutdown error")
	case <-time.After(time.Second):
		t.Fatal("exitFunc was not called within timeout")
	}
}

func TestRegisterProviders(t *testing.T) {
	// Save original registry
	originalRegistry := config.DefaultRegistry
	defer func() { config.DefaultRegistry = originalRegistry }()

	// Create a new registry for testing
	testRegistry := config.NewProviderRegistry()
	config.DefaultRegistry = testRegistry

	// Call registerProviders
	registerProviders()

	// Verify both providers are registered
	providers := testRegistry.List()
	assert.Equal(t, 2, len(providers))

	// Helper to check if string is in slice
	contains := func(slice []string, str string) bool {
		for _, s := range slice {
			if s == str {
				return true
			}
		}
		return false
	}

	assert.True(t, contains(providers, "file"), "file provider should be registered")
	assert.True(t, contains(providers, "docker"), "docker provider should be registered")

	// Verify file provider works
	fileProvider, err := testRegistry.Get("file", config.FileProviderOptions{Path: "/test/path"})
	assert.Nil(t, err)
	assert.NotNil(t, fileProvider)
	assert.Equal(t, "file", fileProvider.Name())

	// Verify docker provider factory is registered
	provider, err := testRegistry.Get("docker", config.DockerProviderOptions{})

	// The important thing is that the provider is registered, not whether it succeeds
	// In CI environments, Docker might be available and creation could succeed
	if err != nil {
		// If there's an error, it should NOT be about the provider not being registered
		assert.NotContains(t, err.Error(), "provider not registered")
	} else {
		// If it succeeds, verify we got a valid provider
		assert.NotNil(t, provider)
		assert.Equal(t, "docker", provider.Name())
	}
}
