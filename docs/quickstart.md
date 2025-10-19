# Quick Start Guide

Get tailnet running in 5 minutes.

## 1. Get OAuth Credentials

1. Go to <https://login.tailscale.com/admin/settings/oauth>
2. Click **Generate OAuth client...**
3. Name it something like `tailnet`
4. Under **Scopes** → **Auth Keys**, check both **Read** and **Write**
5. **Tags**: Select a tag (e.g., `tag:server`) - this tag will be used by your services
6. Click **Generate client**
7. Save the Client ID and Secret

## 2. Create Config File

Create `tailnet.toml`:

```toml
[tailscale]
oauth_client_id_env = "TS_OAUTH_CLIENT_ID"
oauth_client_secret_env = "TS_OAUTH_CLIENT_SECRET"
default_tags = ["tag:server"]  # Must match or be owned by your OAuth client's tag

[[services]]
name = "app"
backend_addr = "localhost:8080"
```

## 3. Run It

```bash
export TS_OAUTH_CLIENT_ID=your-client-id
export TS_OAUTH_CLIENT_SECRET=your-client-secret
tailnet -config tailnet.toml
```

Your service is now available at `https://app.<tailnet>.ts.net`

## Common Patterns

### Multiple Services

```toml
[[services]]
name = "api"
backend_addr = "localhost:8080"

[[services]]
name = "web"
backend_addr = "localhost:3000"
```

### Unix Sockets

```toml
[[services]]
name = "app"
backend_addr = "unix:///var/run/app.sock"
```

### Add Identity Headers

```toml
[[services]]
name = "internal-api"
backend_addr = "localhost:8080"
whois_enabled = true  # Adds X-Tailscale-User headers
```

### Streaming/SSE Support

```toml
[[services]]
name = "events"
backend_addr = "localhost:3000"
write_timeout = "0s"     # No timeout
flush_interval = "-1ms"  # No buffering
```

### Production Setup

```toml
[tailscale]
oauth_client_id_file = "/etc/tailnet/oauth-id"
oauth_client_secret_file = "/etc/tailnet/oauth-secret"
state_dir = "/var/lib/tailnet"
default_tags = ["tag:server", "tag:prod"]

[global]
metrics_addr = ":9090"  # Prometheus metrics

[[services]]
name = "api"
backend_addr = "api.internal:8080"
whois_enabled = true
downstream_headers = {
  "Strict-Transport-Security" = "max-age=63072000"
}
```

## Docker

### With Docker Compose

```yaml
services:
  tailnet:
    image: ghcr.io/sudosu404/tailnet-cli:latest
    command: ["--provider", "docker"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - tailnet-state:/var/lib/tailnet
    environment:
      - TS_OAUTH_CLIENT_ID=${TS_OAUTH_CLIENT_ID}
      - TS_OAUTH_CLIENT_SECRET=${TS_OAUTH_CLIENT_SECRET}
    labels:
      - "tailnet.tailscale.oauth_client_id_env=TS_OAUTH_CLIENT_ID"
      - "tailnet.tailscale.oauth_client_secret_env=TS_OAUTH_CLIENT_SECRET"
      - "tailnet.tailscale.state_dir=/var/lib/tailnet"
      - "tailnet.tailscale.default_tags=tag:server"  # Must match or be owned by your OAuth client's tag

  myapp:
    image: myapp:latest
    labels:
      - "tailnet.enabled=true"
      - "tailnet.service.name=myapp"
      - "tailnet.service.port=8080"
      # Optional: Override default tags for this service
      # - "tailnet.service.tags=tag:api,tag:prod"

volumes:
  tailnet-state:
```

> **Network Requirements**: tailnet and service containers must be on the same Docker network. They don't need to be in the same compose file, but network connectivity is required. See [Docker Labels - Docker Networking](docker-labels.md#docker-networking) for multi-compose setups.

## Troubleshooting

### Validate Your Config

```bash
tailnet -config tailnet.toml -validate
```

### Common Issues

- **"services must have at least one tag"**: Add `default_tags` to `[tailscale]` section
- **"OAuth client ID not set"**: Check your environment variables
- **Connection timeouts**: For streaming, set `write_timeout = "0s"`
- **Tag authorization errors**: Ensure tags match or are owned by your OAuth client's tag. See [Tag Ownership and OAuth Security](configuration-reference.md#tag-ownership-and-oauth-security)

## Next Steps

- See [Configuration Reference](configuration-reference.md) for all options
- Check [Docker Labels](docker-labels.md) for dynamic container management
- Review [examples/](../example/) for complete setups