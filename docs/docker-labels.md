# Docker Labels

Run tailnet in Docker and let it discover services automatically via container labels.

## Quick Example

```yaml
services:
  tailnet:
    image: ghcr.io/sudosu404/tailnet-cli:latest
    command: ["--provider", "docker"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - tailnet-state:/var/lib/tailnet
    environment:
      # Pass the actual OAuth credentials to the container
      - TS_OAUTH_CLIENT_ID=${TS_OAUTH_CLIENT_ID}
      - TS_OAUTH_CLIENT_SECRET=${TS_OAUTH_CLIENT_SECRET}
    labels:
      # Tell tailnet which env vars contain the credentials (not redundant - both are needed)
      - "tailnet.tailscale.oauth_client_id_env=TS_OAUTH_CLIENT_ID"
      - "tailnet.tailscale.oauth_client_secret_env=TS_OAUTH_CLIENT_SECRET"
      - "tailnet.tailscale.state_dir=/var/lib/tailnet"
      - "tailnet.tailscale.default_tags=tag:server" # Must match or be owned by your OAuth client's tag

  myapp:
    image: myapp:latest
    labels:
      - "tailnet.enabled=true"
      - "tailnet.service.name=myapp"
      - "tailnet.service.port=8080"

volumes:
  tailnet-state:
```

Your app is now at `https://myapp.<tailnet>.ts.net`

> **Note**: The `default_tags` must match or be owned by your OAuth client's tag. Individual services can override this with their own `tags` label. See [Tag Ownership and OAuth Security](configuration-reference.md#tag-ownership-and-oauth-security) for setup details.

## How It Works

1. tailnet watches Docker events (no polling!)
2. When a container with `tailnet.enabled=true` starts, it creates a proxy
3. When the container stops, the proxy is removed
4. Changes happen instantly

## Label Reference

### On tailnet Container

```yaml
labels:
  # Required: OAuth setup
  - "tailnet.tailscale.oauth_client_id_env=TS_OAUTH_CLIENT_ID"
  - "tailnet.tailscale.oauth_client_secret_env=TS_OAUTH_CLIENT_SECRET"
  - "tailnet.tailscale.state_dir=/var/lib/tailnet"

  # Optional: defaults
  - "tailnet.tailscale.default_tags=tag:server,tag:proxy"
  - "tailnet.tailscale.oauth_preauthorized=false" # Require manual device approval (default: true)
  - "tailnet.global.metrics_addr=:9090"
  - "tailnet.global.write_timeout=30s"
```

### On Service Containers

```yaml
labels:
  # Required
  - "tailnet.enabled=true"

  # Service config (pick one)
  - "tailnet.service.port=8080" # Recommended
  - "tailnet.service.backend_addr=myservice:8080" # If you need specific host

  # Optional
  - "tailnet.service.name=custom-name" # Default: container name
  - "tailnet.service.whois_enabled=true" # Add identity headers
  - "tailnet.service.tags=tag:api,tag:prod" # Override default tags
  - "tailnet.service.oauth_preauthorized=false" # Override global preauth setting (global default: true)
  - "tailnet.service.listen_addr=0.0.0.0:9090" # Custom address and port
  - "tailnet.service.insecure_skip_verify=true" # Skip TLS cert verification (HTTPS backends only)
```

## Backend Address Tips

**Use port, not localhost:**

```yaml
# Good - uses container name
- "tailnet.service.port=8080"

# Bad - localhost is the tailnet container!
- "tailnet.service.backend_addr=localhost:8080"
```

**Why?** In Docker, each container has its own network namespace. `localhost` inside tailnet doesn't reach your service container.

## Advanced Features

### Custom Listen Configuration

```yaml
labels:
  # Listen on specific address and port
  - "tailnet.service.listen_addr=127.0.0.1:9090"

  # Listen on all interfaces with custom port
  - "tailnet.service.listen_addr=0.0.0.0:8080"

  # Listen on port only (all interfaces)
  - "tailnet.service.listen_addr=:8443"
```

### Streaming/SSE

```yaml
labels:
  - "tailnet.service.write_timeout=0s" # No timeout
  - "tailnet.service.flush_interval=-1ms" # No buffering
```

### Security Headers

```yaml
labels:
  - "tailnet.service.downstream_headers.X-Frame-Options=DENY"
  - "tailnet.service.downstream_headers.Strict-Transport-Security=max-age=31536000"
```

### Custom Headers

```yaml
labels:
  # Add to requests
  - "tailnet.service.upstream_headers.X-Service-Name=api"

  # Remove from responses
  - "tailnet.service.remove_downstream=Server,X-Powered-By"
```

### HTTPS Backends

For connecting to HTTPS backend services:

```yaml
labels:
  # For services with valid certificates
  - "tailnet.service.backend_addr=https://api.example.com:443"

  # For services with self-signed certificates (use with caution)
  - "tailnet.service.backend_addr=https://internal.lan:8443"
  - "tailnet.service.insecure_skip_verify=true"
```

> **⚠️ Security Warning**: `insecure_skip_verify=true` disables TLS certificate validation. Only use this for trusted internal services with self-signed certificates, as it makes connections vulnerable to attacks.

## Complete Example

```yaml
services:
  tailnet:
    image: ghcr.io/sudosu404/tailnet-cli:latest
    command: ["--provider", "docker", "--verbose"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - tailnet-state:/var/lib/tailnet
    networks:
      - app-network
    environment:
      - TS_OAUTH_CLIENT_ID=${TS_OAUTH_CLIENT_ID}
      - TS_OAUTH_CLIENT_SECRET=${TS_OAUTH_CLIENT_SECRET}
    labels:
      - "tailnet.tailscale.oauth_client_id_env=TS_OAUTH_CLIENT_ID"
      - "tailnet.tailscale.oauth_client_secret_env=TS_OAUTH_CLIENT_SECRET"
      - "tailnet.tailscale.state_dir=/var/lib/tailnet"
      - "tailnet.global.metrics_addr=:9090"
    ports:
      - "9090:9090" # Metrics

  api:
    image: myapp/api:latest
    networks:
      - app-network
    labels:
      - "tailnet.enabled=true"
      - "tailnet.service.name=api"
      - "tailnet.service.port=8080"
      - "tailnet.service.whois_enabled=true"

  web:
    image: myapp/web:latest
    networks:
      - app-network
    labels:
      - "tailnet.enabled=true"
      - "tailnet.service.name=web"
      - "tailnet.service.port=3000"
      - "tailnet.service.access_log=false"

volumes:
  tailnet-state:

networks:
  app-network:
```

## Docker Networking

### Network Requirements

tailnet and service containers must be on the same Docker network for communication. They don't need to be in the same compose file, but network connectivity is required.

```yaml
# tailnet can forward traffic to service containers only if they share a network
networks:
  app-network:  # Same network name in both files

# In tailnet compose file
services:
  tailnet:
    networks:
      - app-network

# In service compose file
services:
  myservice:
    networks:
      - app-network
```

### Single Compose File (Simplest)

When everything is in one compose file, Docker automatically creates a shared network:

```yaml
services:
  tailnet:
    image: ghcr.io/sudosu404/tailnet-cli:latest
    command: ["--provider", "docker"]
    # ... other config

  myapp:
    image: myapp:latest
    labels:
      - "tailnet.enabled=true"
      - "tailnet.service.port=8080"
# Both containers automatically share the default network
```

### Multiple Compose Files

For services in separate compose files, use external networks:

**1. Create the network first:**

```bash
docker network create tailnet-network
```

**2. tailnet-compose.yml:**

```yaml
services:
  tailnet:
    image: ghcr.io/sudosu404/tailnet-cli:latest
    command: ["--provider", "docker"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - TS_OAUTH_CLIENT_ID=${TS_OAUTH_CLIENT_ID}
      - TS_OAUTH_CLIENT_SECRET=${TS_OAUTH_CLIENT_SECRET}
    labels:
      - "tailnet.tailscale.oauth_client_id_env=TS_OAUTH_CLIENT_ID"
      - "tailnet.tailscale.oauth_client_secret_env=TS_OAUTH_CLIENT_SECRET"
    networks:
      - tailnet-network

networks:
  tailnet-network:
    external: true
```

**3. services-compose.yml:**

```yaml
services:
  api:
    image: myapi:latest
    labels:
      - "tailnet.enabled=true"
      - "tailnet.service.name=api"
      - "tailnet.service.port=8080"
    networks:
      - tailnet-network

  web:
    image: myweb:latest
    labels:
      - "tailnet.enabled=true"
      - "tailnet.service.name=web"
      - "tailnet.service.port=3000"
    networks:
      - tailnet-network

networks:
  tailnet-network:
    external: true
```

**4. Start them:**

```bash
# Start tailnet
docker compose -f tailnet-compose.yml up -d

# Start services (in any order)
docker compose -f services-compose.yml up -d
```

### Alternative: Define Network in One File

You can also define the network in one compose file and reference it as external in others:

**tailnet-compose.yml (defines network):**

```yaml
services:
  tailnet:
    # ... config
    networks:
      - shared-network

networks:
  shared-network:
    name: tailnet-shared
```

**services-compose.yml (uses external network):**

```yaml
services:
  myapp:
    # ... config
    networks:
      - shared-network

networks:
  shared-network:
    external: true
    name: tailnet-shared
```

### Network Troubleshooting

**Why does networking matter?**

- tailnet acts as a reverse proxy
- It needs to reach your service containers over the network
- `localhost` inside tailnet container ≠ service containers
- Docker networks enable container-to-container communication

**Common networking issues:**

**Service not appearing?**

- Check `tailnet.enabled=true` is set
- Verify containers are on same network - use `docker network ls` and `docker inspect <container>`
- Look at tailnet logs with `--verbose`

**Connection refused?**

- Don't use `localhost` - use `port` label instead
- Make sure service is listening on the port
- Check container is actually running
- Verify network connectivity: `docker exec tailnet-container ping service-container`

**Cross-compose networking not working?**

- Ensure both compose files reference the same network name
- Check network exists: `docker network ls`
- Verify containers joined the network: `docker network inspect <network-name>`
- Make sure network is external in dependent compose files

## Troubleshooting

**Label changes ignored?**

- Labels are only read when container starts
- Restart container to apply new labels

**Cannot connect between compose files?**

- Ensure both files use the same network name
- Network must be marked as `external: true` in dependent compose files
- Create network manually if needed: `docker network create <network-name>`
