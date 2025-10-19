# Examples

Working examples of tailnet configurations.

## simple/

Basic setup with TOML config:

```bash
cd simple
export TS_OAUTH_CLIENT_ID="your-client-id"
export TS_OAUTH_CLIENT_SECRET="your-client-secret"
docker compose up
```

## docker-labels/

Dynamic service discovery via Docker labels:

```bash
cd docker-labels
export TS_OAUTH_CLIENT_ID="your-client-id"
export TS_OAUTH_CLIENT_SECRET="your-client-secret"
docker compose up
```

## multi-compose/

tailnet and services in separate compose files with shared networking:

```bash
cd multi-compose
export TS_OAUTH_CLIENT_ID="your-client-id"
export TS_OAUTH_CLIENT_SECRET="your-client-secret"

# Start tailnet first (creates shared network)
docker compose -f tailnet-compose.yml up -d

# Start services (uses external network) 
docker compose -f services-compose.yml up -d
```

## headscale/

Self-hosted control server with Headscale:

```bash
cd headscale
docker compose up -d

# Create user and auth key
docker compose exec headscale headscale users create testuser
docker compose exec headscale headscale --user 1 preauthkeys create --reusable --expiration 90d

# Set auth key and restart
export TS_AUTHKEY="<auth-key-from-above>"
docker compose up -d tailnet tailscale-client
```

## backend/

Shared test backend that echoes request info and shows Tailscale headers.

## Common Tasks

```bash
# Logs
docker compose logs -f tailnet

# Metrics
curl http://localhost:9090

# Cleanup
docker compose down -v
```
