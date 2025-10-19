# Multi-Compose Example

This example demonstrates how to run tailnet and services in separate Docker Compose files while maintaining network connectivity.

## Overview

This setup uses two compose files:

- `tailnet-compose.yml` - Runs tailnet proxy with Docker provider
- `services-compose.yml` - Runs application services with tailnet labels

The key is that both files reference the same Docker network (`tailnet-shared-network`), allowing tailnet to forward traffic to service containers.

## Network Strategy

1. **tailnet-compose.yml** creates the network (`tailnet-shared-network`)
2. **services-compose.yml** uses the network as external
3. All containers can communicate because they're on the same network

## Prerequisites

1. Get OAuth credentials from [Tailscale Admin Console](https://login.tailscale.com/admin/settings/oauth)
2. Export them as environment variables:

```bash
export TS_OAUTH_CLIENT_ID="your-client-id"
export TS_OAUTH_CLIENT_SECRET="your-client-secret"
```

## Running the Example

### Option 1: Start tailnet first (recommended)

```bash
# Start tailnet (creates the network)
docker compose -f tailnet-compose.yml up -d

# Start services (uses existing network)
docker compose -f services-compose.yml up -d
```

### Option 2: Create network manually first

```bash
# Create network manually
docker network create tailnet-shared-network

# Start both (any order)
docker compose -f tailnet-compose.yml up -d
docker compose -f services-compose.yml up -d
```

## Accessing Services

After both compose files are running:

- Whoami service: `https://whoami.<tailnet>.ts.net` (with whois headers)
- Metrics: `http://localhost:9090` (from host machine)

## Logs and Debugging

```bash
# Check tailnet logs
docker compose -f tailnet-compose.yml logs -f tailnet

# Check service logs
docker compose -f services-compose.yml logs -f whoami

# Verify network connectivity
docker network inspect tailnet-shared-network

# Test connectivity between containers
docker exec -it multi-compose-tailnet-1 ping whoami
```

## Stopping

```bash
# Stop services
docker compose -f services-compose.yml down

# Stop tailnet
docker compose -f tailnet-compose.yml down

# Clean up (removes network and volumes)
docker compose -f tailnet-compose.yml down -v
docker compose -f services-compose.yml down -v
```

## Why This Works

1. **Network Sharing**: Both compose files reference the same Docker network name
2. **Service Discovery**: tailnet watches Docker events across all networks it's connected to
3. **Container Resolution**: Service labels use `port` which resolves to the container name + that port
4. **Automatic Proxy**: When containers start/stop, tailnet automatically adds/removes proxies

## Troubleshooting

**Services not appearing in tailnet?**

- Ensure containers have `tailnet.enabled=true` label
- Check both containers are on the same network: `docker network inspect tailnet-shared-network`
- Look at tailnet logs: `docker compose -f tailnet-compose.yml logs tailnet`

**Network connection refused?**

- Verify service is listening on the specified port
- Test connectivity: `docker exec tailnet-container ping service-container`
- Check service containers are running: `docker compose -f services-compose.yml ps`

**Network not found errors?**

- Start tailnet first (it creates the network) OR
- Create network manually: `docker network create tailnet-shared-network`
