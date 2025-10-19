# systemd Deployment

Systemd service files for running tailnet on Linux.

## Quick Install

```bash
# 1. Create user
sudo useradd --system --shell /bin/false --home-dir /var/lib/tailnet --create-home tailnet

# 2. Install binary
sudo install -o root -g root -m 755 tailnet /usr/local/bin/

# 3. Create config directory
sudo install -d -o tailnet -g tailnet -m 755 /etc/tailnet

# 4. Install your config
sudo install -o tailnet -g tailnet -m 640 config.toml /etc/tailnet/
sudo install -o tailnet -g tailnet -m 600 tailnet.env.example /etc/tailnet/tailnet.env

# 5. Install service
sudo install -m 644 tailnet.service /etc/systemd/system/
sudo systemctl daemon-reload

# 6. Start it
sudo systemctl start tailnet
sudo systemctl enable tailnet
```

## Configuration

### Environment File (`/etc/tailnet/tailnet.env`)

```bash
TS_OAUTH_CLIENT_ID=your-client-id
TS_OAUTH_CLIENT_SECRET=your-client-secret
```

### Config File (`/etc/tailnet/config.toml`)

```toml
[tailscale]
# OAuth credentials come from environment
state_dir = "/var/lib/tailnet"  # Or omit - systemd sets STATE_DIRECTORY
default_tags = ["tag:server"]
# oauth_preauthorized = false  # Require manual device approval (default: true)

[global]
metrics_addr = ":9090"

[[services]]
name = "your-service"
backend_addr = "localhost:8080"
```

## State Directory

The service uses `StateDirectory=tailnet` which means:
- systemd creates `/var/lib/tailnet` automatically
- Sets `STATE_DIRECTORY` environment variable
- tailnet detects this automatically (no config needed)

## Security Features

The service file includes hardening:
- Read-only filesystem (`ProtectSystem=strict`)
- No access to /home (`ProtectHome=true`)
- Limited network access (`RestrictAddressFamilies`)
- No privilege escalation (`NoNewPrivileges`)

## Troubleshooting

```bash
# View logs
sudo journalctl -u tailnet -f

# Validate config
sudo -u tailnet /usr/local/bin/tailnet -config /etc/tailnet/config.toml -validate

# Restart
sudo systemctl restart tailnet
```

### Common Issues

**"netlinkrib: address family not supported"**
- Already fixed in service file with `AF_NETLINK`
- If you see it: `sudo systemctl daemon-reload && sudo systemctl restart tailnet`

**Service won't start?**
1. Check binary is executable
2. Validate config file
3. Verify OAuth credentials are set
4. Check port conflicts

## Files

- `tailnet.service` - systemd service unit
- `tailnet.env.example` - Example environment file