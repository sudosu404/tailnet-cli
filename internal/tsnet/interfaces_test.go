package tsnet

import (
	"context"
	"net"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

func TestTSNetServerInterface(t *testing.T) {
	t.Run("RealTSNetServer implements TSNetServer", func(t *testing.T) {
		// This test ensures RealTSNetServer properly implements the interface
		var _ TSNetServer = (*RealTSNetServer)(nil)
	})

	t.Run("MockTSNetServer implements TSNetServer", func(t *testing.T) {
		// This test ensures MockTSNetServer properly implements the interface
		var _ TSNetServer = (*MockTSNetServer)(nil)
	})
}

func TestRealTSNetServer(t *testing.T) {
	t.Run("wraps tsnet.Server properly", func(t *testing.T) {
		server := NewRealTSNetServer()
		server.SetHostname("test-host")
		server.SetDir("/tmp/test")
		server.SetAuthKey("test-key")
		server.Logf = logger.Discard

		if server.Hostname != "test-host" {
			t.Errorf("expected hostname test-host, got %s", server.Hostname)
		}
		if server.Dir != "/tmp/test" {
			t.Errorf("expected dir /tmp/test, got %s", server.Dir)
		}
		if server.AuthKey != "test-key" {
			t.Errorf("expected authkey test-key, got %s", server.AuthKey)
		}
	})

	t.Run("delegates methods to wrapped server", func(t *testing.T) {
		// Since we can't easily test real tsnet.Server methods without
		// network access, we'll just ensure the methods exist and are callable
		server := NewRealTSNetServer()
		server.SetDir(t.TempDir())
		server.Logf = logger.Discard

		// These would fail in a test environment without real Tailscale setup,
		// but we're ensuring the methods exist and delegate properly
		_ = server.Listen
		_ = server.Close
		_ = server.Start
		_ = server.LocalClient
	})
}

func TestMockTSNetServer(t *testing.T) {
	t.Run("can be configured for testing", func(t *testing.T) {
		mock := NewMockTSNetServer()
		mock.Hostname = "mock-host"
		mock.Dir = "/mock/dir"
		mock.AuthKey = "mock-key"

		if mock.Hostname != "mock-host" {
			t.Errorf("expected hostname mock-host, got %s", mock.Hostname)
		}
		if mock.Dir != "/mock/dir" {
			t.Errorf("expected dir /mock/dir, got %s", mock.Dir)
		}
		if mock.AuthKey != "mock-key" {
			t.Errorf("expected authkey mock-key, got %s", mock.AuthKey)
		}
	})

	t.Run("SetHostname sets hostname", func(t *testing.T) {
		mock := NewMockTSNetServer()
		mock.SetHostname("new-hostname")
		if mock.Hostname != "new-hostname" {
			t.Errorf("expected hostname new-hostname, got %s", mock.Hostname)
		}
	})

	t.Run("SetDir sets directory", func(t *testing.T) {
		mock := NewMockTSNetServer()
		mock.SetDir("/new/dir")
		if mock.Dir != "/new/dir" {
			t.Errorf("expected dir /new/dir, got %s", mock.Dir)
		}
	})

	t.Run("SetAuthKey sets auth key", func(t *testing.T) {
		mock := NewMockTSNetServer()
		mock.SetAuthKey("new-auth-key")
		if mock.AuthKey != "new-auth-key" {
			t.Errorf("expected authkey new-auth-key, got %s", mock.AuthKey)
		}
	})

	t.Run("Listen returns configured listener", func(t *testing.T) {
		mock := NewMockTSNetServer()
		expectedListener := &net.TCPListener{}
		mock.ListenFunc = func(network, addr string) (net.Listener, error) {
			return expectedListener, nil
		}

		listener, err := mock.Listen("tcp", ":80")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if listener != expectedListener {
			t.Error("listener was not the expected one")
		}
	})

	t.Run("Close calls CloseFunc", func(t *testing.T) {
		mock := NewMockTSNetServer()
		called := false
		mock.CloseFunc = func() error {
			called = true
			return nil
		}

		err := mock.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Error("CloseFunc was not called")
		}
	})

	t.Run("Start calls StartFunc", func(t *testing.T) {
		mock := NewMockTSNetServer()
		called := false
		mock.StartFunc = func() error {
			called = true
			return nil
		}

		err := mock.Start()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Error("StartFunc was not called")
		}
	})

	t.Run("LocalClient returns configured client", func(t *testing.T) {
		mock := NewMockTSNetServer()
		expectedClient := &MockLocalClient{
			WhoIsFunc: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{
					UserProfile: &tailcfg.UserProfile{
						LoginName: "test-user",
					},
					Node: &tailcfg.Node{
						Name: "test-node",
					},
				}, nil
			},
		}
		mock.LocalClientFunc = func() (LocalClient, error) {
			return expectedClient, nil
		}

		client, err := mock.LocalClient()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Test that the client works as expected
		info, err := client.WhoIs(context.Background(), "1.2.3.4:80")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.UserProfile == nil || info.UserProfile.LoginName != "test-user" {
			t.Errorf("expected LoginName test-user, got %v", info.UserProfile)
		}
		if info.Node == nil || info.Node.Name != "test-node" {
			t.Errorf("expected Node.Name test-node, got %v", info.Node)
		}
	})
}

func TestTSNetServerFactory(t *testing.T) {
	t.Run("creates new instances", func(t *testing.T) {
		factory := func() TSNetServer {
			return NewMockTSNetServer()
		}

		server1 := factory()
		server2 := factory()

		// Ensure they are different instances
		if server1 == server2 {
			t.Error("factory should create new instances")
		}
	})
}

func TestMockLocalClient(t *testing.T) {
	t.Run("WhoIs returns configured response", func(t *testing.T) {
		mock := &MockLocalClient{
			WhoIsFunc: func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
				if remoteAddr == "192.168.1.1:443" {
					return &apitype.WhoIsResponse{
						UserProfile: &tailcfg.UserProfile{
							LoginName: "admin@example.com",
						},
						Node: &tailcfg.Node{
							Name: "admin-node",
						},
					}, nil
				}
				return nil, nil
			},
		}

		// Test successful WhoIs
		resp, err := mock.WhoIs(context.Background(), "192.168.1.1:443")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.UserProfile == nil || resp.UserProfile.LoginName != "admin@example.com" {
			t.Errorf("expected LoginName admin@example.com, got %v", resp)
		}

		// Test unknown address
		resp, err = mock.WhoIs(context.Background(), "10.0.0.1:80")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil {
			t.Errorf("expected nil response for unknown address, got %v", resp)
		}
	})

	t.Run("WhoIs with nil function returns nil", func(t *testing.T) {
		mock := &MockLocalClient{}

		resp, err := mock.WhoIs(context.Background(), "any-address")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil {
			t.Errorf("expected nil response when WhoIsFunc is nil, got %v", resp)
		}
	})
}

func TestMockTSNetServerCustomization(t *testing.T) {
	t.Run("with start error", func(t *testing.T) {
		expectedErr := context.DeadlineExceeded
		mock := NewMockTSNetServer()
		mock.StartFunc = func() error {
			return expectedErr
		}

		err := mock.Start()
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("with close error", func(t *testing.T) {
		expectedErr := context.Canceled
		mock := NewMockTSNetServer()
		mock.CloseFunc = func() error {
			return expectedErr
		}

		err := mock.Close()
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("with custom listen function", func(t *testing.T) {
		mock := NewMockTSNetServer()
		mock.ListenFunc = func(network, addr string) (net.Listener, error) {
			if network == "tcp" && addr == ":9090" {
				// Return a valid listener
				return &testListener{
					addr: testAddr{
						network: "tcp",
						address: "127.0.0.1:9090",
					},
				}, nil
			}
			return nil, net.ErrClosed
		}

		// Test custom listener
		listener, err := mock.Listen("tcp", ":9090")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if listener == nil {
			t.Error("expected non-nil listener")
		}

		// Test error case
		_, err = mock.Listen("tcp", ":8080")
		if err != net.ErrClosed {
			t.Errorf("expected net.ErrClosed, got %v", err)
		}
	})

	t.Run("with custom local client function", func(t *testing.T) {
		customClient := &MockLocalClient{
			WhoIsFunc: func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{
					UserProfile: &tailcfg.UserProfile{
						LoginName: "custom@test.com",
					},
				}, nil
			},
		}
		mock := NewMockTSNetServer()
		mock.LocalClientFunc = func() (LocalClient, error) {
			return customClient, nil
		}

		client, err := mock.LocalClient()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp, err := client.WhoIs(context.Background(), "any")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.UserProfile.LoginName != "custom@test.com" {
			t.Errorf("expected LoginName custom@test.com, got %s", resp.UserProfile.LoginName)
		}
	})
}

// Test helpers - use different names to avoid conflicts
type testListener struct {
	addr testAddr
}

func (t *testListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (t *testListener) Close() error {
	return nil
}

func (t *testListener) Addr() net.Addr {
	return t.addr
}

type testAddr struct {
	network string
	address string
}

func (t testAddr) Network() string {
	return t.network
}

func (t testAddr) String() string {
	return t.address
}
