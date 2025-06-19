package tailscale

import (
	"os"
	"path/filepath"
)

// hasExistingState checks if a service has existing tsnet state
func hasExistingState(stateDir string, serviceName string) bool {
	// Each service has its own subdirectory under the state directory
	serviceStateDir := filepath.Join(stateDir, serviceName)

	// Check if the directory exists
	info, err := os.Stat(serviceStateDir)
	if err != nil || !info.IsDir() {
		return false
	}

	// Check for key state files that indicate an initialized node
	// tsnet stores various state files, but the key ones are:
	// - tailscaled.state: The main state file
	// - tailscaled.log.conf: Logging configuration
	stateFile := filepath.Join(serviceStateDir, "tailscaled.state")
	if _, err := os.Stat(stateFile); err == nil {
		return true
	}

	return false
}
