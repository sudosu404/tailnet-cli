// Package tailscale manages Tailscale server instances and lifecycle.
package tailscale

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/adrg/xdg"
	"github.com/jtdowney/tsbridge/internal/config"
	tserrors "github.com/jtdowney/tsbridge/internal/errors"
	tsnetpkg "github.com/jtdowney/tsbridge/internal/tsnet"
)

// Server wraps a tsnet.Server with tsbridge-specific functionality
type Server struct {
	config config.Tailscale
	// serviceServers holds the tsnet.Server instance for each service
	serviceServers map[string]tsnetpkg.TSNetServer
	// serverFactory creates new TSNetServer instances
	serverFactory tsnetpkg.TSNetServerFactory
	// mu protects serviceServers map
	mu sync.Mutex
}

// NewServerWithFactory creates a new tailscale server instance with a custom TSNetServer factory
func NewServerWithFactory(cfg config.Tailscale, factory tsnetpkg.TSNetServerFactory) (*Server, error) {
	// Config package has already resolved all secrets, so we can use them directly
	authKey := cfg.AuthKey
	clientID := cfg.OAuthClientID
	clientSecret := cfg.OAuthClientSecret

	// Validate we have either AuthKey or OAuth credentials
	if authKey == "" && (clientID == "" || clientSecret == "") {
		// Provide more specific error message
		switch {
		case clientID == "" && clientSecret == "":
			return nil, tserrors.NewConfigError("either auth key or OAuth credentials (client ID and secret) must be provided")
		case clientID == "":
			return nil, tserrors.NewConfigError("OAuth client ID is required when using OAuth authentication")
		default:
			return nil, tserrors.NewConfigError("OAuth client secret is required when using OAuth authentication")
		}
	}

	return &Server{
		config:         cfg,
		serviceServers: make(map[string]tsnetpkg.TSNetServer),
		serverFactory:  factory,
	}, nil
}

// NewServer creates a new tailscale server instance
func NewServer(cfg config.Tailscale) (*Server, error) {
	// Default factory creates real TSNet servers
	factory := func() tsnetpkg.TSNetServer {
		return tsnetpkg.NewRealTSNetServer()
	}

	return NewServerWithFactory(cfg, factory)
}

// Listen creates a listener for a specific service
func (s *Server) Listen(serviceName string, tlsMode string, funnelEnabled bool) (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create a new server for this service
	serviceServer := s.serverFactory()

	// Configure the service server
	serviceServer.SetHostname(serviceName)

	// Priority for state directory
	stateDir := s.config.StateDir
	if stateDir == "" {
		stateDir = os.Getenv("TSBRIDGE_STATE_DIR")
	}
	if stateDir == "" {
		// Use XDG data directory as default
		stateDir = getDefaultStateDir()
	}
	// Each service needs its own unique state directory to avoid conflicts
	// when multiple tsnet.Server instances write to the same directory
	serviceStateDir := filepath.Join(stateDir, serviceName)
	serviceServer.SetDir(serviceStateDir)

	// Check if this service already has state
	// If state exists, tsnet will use it and doesn't need an auth key
	if !hasExistingState(stateDir, serviceName) {
		// Generate or resolve auth key with OAuth support only for new nodes
		cfg := config.Config{
			Tailscale: s.config,
		}
		authKey, err := generateOrResolveAuthKey(cfg)
		if err != nil {
			return nil, tserrors.WrapConfig(err, fmt.Sprintf("resolving auth key for service %q", serviceName))
		}
		serviceServer.SetAuthKey(authKey)
	}
	// If state exists, we don't set an auth key - tsnet will use the stored state

	// Store the service server for later operations
	s.serviceServers[serviceName] = serviceServer

	// Start the service server before listening
	if err := serviceServer.Start(); err != nil {
		return nil, tserrors.WrapResource(err, fmt.Sprintf("starting tsnet server for service %q", serviceName))
	}

	// Choose the appropriate listener based on TLS mode and funnel settings
	if funnelEnabled {
		// Funnel requires HTTPS on port 443
		return serviceServer.ListenFunnel("tcp", ":443")
	}

	switch tlsMode {
	case "auto":
		// Use ListenTLS for automatic TLS certificate provisioning
		return serviceServer.ListenTLS("tcp", ":443")
	case "off":
		// Use plain Listen without TLS (traffic still encrypted via WireGuard)
		return serviceServer.Listen("tcp", ":80")
	default:
		return nil, tserrors.NewValidationError(fmt.Sprintf("invalid TLS mode: %q", tlsMode))
	}
}

// ListenWithService creates a listener for a specific service using its full configuration
func (s *Server) ListenWithService(svc config.Service, tlsMode string, funnelEnabled bool) (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create a new server for this service
	serviceServer := s.serverFactory()

	// Configure the service server
	serviceServer.SetHostname(svc.Name)
	serviceServer.SetEphemeral(svc.Ephemeral)

	// Priority for state directory
	stateDir := s.config.StateDir
	if stateDir == "" {
		stateDir = os.Getenv("TSBRIDGE_STATE_DIR")
	}
	if stateDir == "" {
		// Use XDG data directory as default
		stateDir = getDefaultStateDir()
	}
	// Each service needs its own unique state directory to avoid conflicts
	// when multiple tsnet.Server instances write to the same directory
	serviceStateDir := filepath.Join(stateDir, svc.Name)
	serviceServer.SetDir(serviceStateDir)

	// Check if this service already has state
	// If state exists, tsnet will use it and doesn't need an auth key
	if !hasExistingState(stateDir, svc.Name) {
		// Generate or resolve auth key with OAuth support only for new nodes
		cfg := config.Config{
			Tailscale: s.config,
		}
		authKey, err := generateOrResolveAuthKey(cfg)
		if err != nil {
			return nil, tserrors.WrapConfig(err, fmt.Sprintf("resolving auth key for service %q", svc.Name))
		}
		serviceServer.SetAuthKey(authKey)
	}
	// If state exists, we don't set an auth key - tsnet will use the stored state

	// Store the service server for later operations
	s.serviceServers[svc.Name] = serviceServer

	// Start the service server before listening
	if err := serviceServer.Start(); err != nil {
		return nil, tserrors.WrapResource(err, fmt.Sprintf("starting tsnet server for service %q", svc.Name))
	}

	// Choose the appropriate listener based on TLS mode and funnel settings
	if funnelEnabled {
		// Funnel requires HTTPS on port 443
		return serviceServer.ListenFunnel("tcp", ":443")
	}

	switch tlsMode {
	case "auto":
		// Use ListenTLS for automatic TLS certificate provisioning
		return serviceServer.ListenTLS("tcp", ":443")
	case "off":
		// Use plain Listen without TLS (traffic still encrypted via WireGuard)
		return serviceServer.Listen("tcp", ":80")
	default:
		return nil, tserrors.NewValidationError(fmt.Sprintf("invalid TLS mode: %q", tlsMode))
	}
}

// GetServiceServer returns the TSNetServer for a specific service
func (s *Server) GetServiceServer(serviceName string) tsnetpkg.TSNetServer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serviceServers[serviceName]
}

// Close shuts down the server and all service servers
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var closeErrors []error

	// Close all service servers
	for serviceName, server := range s.serviceServers {
		if err := server.Close(); err != nil {
			closeErrors = append(closeErrors, tserrors.WrapResource(err, fmt.Sprintf("closing service %q", serviceName)))
		}
	}

	// Clear the map after closing
	s.serviceServers = make(map[string]tsnetpkg.TSNetServer)

	// Combine errors if any occurred
	if len(closeErrors) > 0 {
		return errors.Join(closeErrors...)
	}

	return nil
}

// ValidateTailscaleSecrets validates that either auth key or OAuth credentials are present.
// The actual validation and resolution is done by the config package.
func ValidateTailscaleSecrets(cfg config.Tailscale) error {
	// Config package has already resolved all secrets, so we just check if they exist
	if cfg.AuthKey != "" {
		return nil // Auth key is available, no need for OAuth
	}

	// Check if OAuth credentials are available
	if cfg.OAuthClientID != "" && cfg.OAuthClientSecret != "" {
		return nil
	}

	// If neither auth key nor complete OAuth credentials are available, return error
	if cfg.OAuthClientID == "" && cfg.OAuthClientSecret == "" {
		return tserrors.NewConfigError("either auth key or OAuth credentials (client ID and secret) must be provided")
	}

	// One OAuth credential is missing
	if cfg.OAuthClientID == "" {
		return tserrors.NewConfigError("OAuth client ID is missing")
	}
	return tserrors.NewConfigError("OAuth client secret is missing")
}

// getDefaultStateDir returns the default state directory using platform-specific paths
func getDefaultStateDir() string {
	// Use XDG data directory which handles cross-platform paths correctly
	return filepath.Join(xdg.DataHome, "tsbridge")
}
