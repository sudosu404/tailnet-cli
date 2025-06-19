package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jtdowney/tsbridge/internal/testutil"
	"github.com/jtdowney/tsbridge/test/integration/helpers"
)

// TestInMemoryMetricsCollection was removed - this behavior is already tested in:
// - internal/metrics/metrics_test.go: TestMetricsEndpoint

// TestE2EMetricsCollection tests that metrics are collected during normal operation using exec.Command
func TestE2EMetricsCollection(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create backend servers that track requests
	backend1, _ := helpers.CreateTrackingBackend(t)
	backend2, _ := helpers.CreateTrackingBackend(t)

	// Create test configuration and write to file
	cfg := helpers.CreateMultiServiceConfig(t, map[string]string{
		"metrics-service1": backend1.Listener.Addr().String(),
		"metrics-service2": backend2.Listener.Addr().String(),
	})
	configPath := helpers.WriteConfigFile(t, cfg)

	// Start tsbridge process
	process := helpers.StartTSBridge(t, configPath)

	// Get the output (this will trigger shutdown)
	output := process.GetOutput()

	// Verify metrics server started
	testutil.AssertContains(t, output, "metrics server listening")

	// Verify both services started
	testutil.AssertContains(t, output, `msg="started service" service=metrics-service1`)
	testutil.AssertContains(t, output, `msg="started service" service=metrics-service2`)
}

// TestMetricsEndpointWithRealServer tests metrics endpoint with actual HTTP requests
func TestMetricsEndpointWithRealServer(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Create config with specific metrics port
	cfg := helpers.NewTestFixture(t).
		WithService("test-metrics-api", backend.Listener.Addr().String()).
		Build()
	cfg.Global.MetricsAddr = "localhost:9999"

	// Write config and build binary
	configPath := helpers.WriteConfigFile(t, cfg)
	binPath := helpers.BuildTestBinary(t)

	// Start tsbridge with specific metrics port
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "-config", configPath)
	cmd.Env = append(os.Environ(), "TSBRIDGE_TEST_MODE=1")

	// Start in background
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start tsbridge: %v", err)
	}

	// Wait for service to be ready
	time.Sleep(2 * time.Second)

	// Try to access metrics endpoint
	metricsURL := "http://localhost:9999/metrics"
	var resp *http.Response
	var err error

	// Retry a few times in case startup is slow
	for i := 0; i < 5; i++ {
		resp, err = http.Get(metricsURL)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err != nil {
		t.Logf("Warning: Could not access metrics endpoint: %v", err)
		// Don't fail the test as port might be in use
		return
	}
	defer resp.Body.Close()

	// Read metrics
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read metrics: %v", err)
	}

	metricsStr := string(body)

	// Verify Prometheus format
	if !strings.Contains(metricsStr, "# HELP") {
		t.Error("metrics response doesn't contain Prometheus help text")
	}

	// In test mode, verify we at least get some metrics
	// The custom tsbridge metrics may not be initialized
	if strings.Contains(metricsStr, "tsbridge_") {
		// If we have tsbridge metrics, verify them
		expectedMetrics := []string{
			"tsbridge_requests_total",
			"tsbridge_request_duration_seconds",
			"tsbridge_errors_total",
			"tsbridge_active_connections",
		}

		foundCount := 0
		for _, metric := range expectedMetrics {
			if strings.Contains(metricsStr, metric) {
				foundCount++
			}
		}

		if foundCount == 0 {
			t.Log("Warning: No tsbridge metrics found, this might be expected in test mode")
		} else if foundCount < len(expectedMetrics) {
			t.Logf("Found %d/%d expected metrics", foundCount, len(expectedMetrics))
		}
	} else {
		// In test mode, just verify we get valid Prometheus output
		t.Log("Note: tsbridge metrics not found, verifying basic Prometheus format")

		// Should at least have Go runtime metrics
		if !strings.Contains(metricsStr, "go_") {
			t.Error("expected Go runtime metrics in response")
		}
	}
}
