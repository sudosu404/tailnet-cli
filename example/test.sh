#!/bin/bash

# Simple test script for tsbridge example

set -e

echo "=== tsbridge Example Test Script ==="
echo

# Check if OAuth credentials are set
if [ -z "$TS_OAUTH_CLIENT_ID" ] || [ -z "$TS_OAUTH_CLIENT_SECRET" ]; then
    echo "ERROR: Please set TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET environment variables"
    echo "You can get these from: https://login.tailscale.com/admin/settings/oauth"
    exit 1
fi

echo "✓ OAuth credentials found"
echo

# Start services
echo "Starting services..."
docker-compose up -d --build

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 10

# Check if tsbridge is running
if docker-compose ps | grep -q "tsbridge.*Up"; then
    echo "✓ tsbridge is running"
else
    echo "✗ tsbridge failed to start"
    echo "Logs:"
    docker-compose logs tsbridge
    exit 1
fi

# Check backend services
for service in api-backend web-backend; do
    if docker-compose ps | grep -q "$service.*Up"; then
        echo "✓ $service is running"
    else
        echo "✗ $service failed to start"
        exit 1
    fi
done

echo
echo "Testing local backend endpoints..."

# Test api backend
if curl -s http://localhost:8080/health | grep -q "healthy"; then
    echo "✓ API backend is healthy"
else
    echo "✗ API backend health check failed"
fi

# Test web backend
if curl -s http://localhost:8081/health | grep -q "healthy"; then
    echo "✓ Web backend is healthy"
else
    echo "✗ Web backend health check failed"
fi

echo
echo "Checking metrics endpoint..."
if curl -s http://localhost:9090/metrics | grep -q "tsbridge_"; then
    echo "✓ Metrics endpoint is working"
else
    echo "✗ Metrics endpoint not responding"
fi

echo
echo "=== Services are running! ==="
echo
echo "tsbridge logs:"
docker-compose logs --tail=20 tsbridge

echo
echo "Your services should be available at:"
echo "  - https://demo-api.<your-tailnet>.ts.net"
echo "  - https://demo-web.<your-tailnet>.ts.net"
echo "  - https://demo-slow.<your-tailnet>.ts.net"
echo
echo "To view logs:    docker-compose logs -f"
echo "To stop:         docker-compose down"
echo "To cleanup:      docker-compose down -v"