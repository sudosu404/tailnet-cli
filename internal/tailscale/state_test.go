package tailscale

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasExistingState(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(tmpDir string) error
		serviceName    string
		expectedResult bool
	}{
		{
			name:           "no state directory exists",
			setupFunc:      func(tmpDir string) error { return nil },
			serviceName:    "test-service",
			expectedResult: false,
		},
		{
			name: "state directory exists but no state file",
			setupFunc: func(tmpDir string) error {
				return os.MkdirAll(filepath.Join(tmpDir, "test-service"), 0755)
			},
			serviceName:    "test-service",
			expectedResult: false,
		},
		{
			name: "state directory and state file exist",
			setupFunc: func(tmpDir string) error {
				serviceDir := filepath.Join(tmpDir, "test-service")
				if err := os.MkdirAll(serviceDir, 0755); err != nil {
					return err
				}
				stateFile := filepath.Join(serviceDir, "tailscaled.state")
				return os.WriteFile(stateFile, []byte("mock-state"), 0644)
			},
			serviceName:    "test-service",
			expectedResult: true,
		},
		{
			name: "wrong service name",
			setupFunc: func(tmpDir string) error {
				serviceDir := filepath.Join(tmpDir, "other-service")
				if err := os.MkdirAll(serviceDir, 0755); err != nil {
					return err
				}
				stateFile := filepath.Join(serviceDir, "tailscaled.state")
				return os.WriteFile(stateFile, []byte("mock-state"), 0644)
			},
			serviceName:    "test-service",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if err := tt.setupFunc(tmpDir); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			result := hasExistingState(tmpDir, tt.serviceName)
			if result != tt.expectedResult {
				t.Errorf("hasExistingState() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}
