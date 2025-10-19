# FreeBSD Deployment Guide for tailnet

This guide covers deploying tailnet on FreeBSD systems using the rc.d init system.

## Prerequisites

- FreeBSD
- Go 1.24+ (for building from source)
- Tailscale OAuth client credentials

## Installation

### Option 1: Download Pre-built Binary

Download the latest FreeBSD binary from the [releases page](https://github.com/sudosu404/tailnet-cli/releases):

```bash
# For amd64
fetch https://github.com/sudosu404/tailnet-cli/releases/latest/download/tsbridge_VERSION_freebsd_amd64.tar.gz
tar -xzf tsbridge_VERSION_freebsd_amd64.tar.gz
install -m 755 tailnet /usr/local/bin/

# For arm64
fetch https://github.com/sudosu404/tailnet-cli/releases/latest/download/tsbridge_VERSION_freebsd_arm64.tar.gz
tar -xzf tsbridge_VERSION_freebsd_arm64.tar.gz
install -m 755 tailnet /usr/local/bin/
```

### Option 2: Build from Source

```bash
git clone https://github.com/sudosu404/tailnet-cli.git
cd tailnet
make build
install -m 755 tailnet /usr/local/bin/
```

## System Setup

### 1. Create User and Group

```bash
# Create tailnet user and group
pw groupadd tailnet
pw useradd tailnet -g tailnet -d /nonexistent -s /usr/sbin/nologin -c "tailnet daemon"
```

### 2. Create Required Directories

```bash
# Configuration directory
install -d -o root -g wheel -m 755 /usr/local/etc/tailnet

# Runtime directories (will be created by rc script, but can be pre-created)
install -d -o tailnet -g tailnet -m 750 /var/run/tailnet
install -d -o tailnet -g tailnet -m 750 /var/log/tailnet
install -d -o tailnet -g tailnet -m 750 /var/db/tailnet
```

### 3. Install Configuration

Copy the example configuration and customize it:

```bash
cp /path/to/tailnet/deployments/freebsd/config.example.toml /usr/local/etc/tailnet/config.toml
```

Basic configuration example at `/usr/local/etc/tailnet/config.toml`:

```toml
# Tailscale authentication (required)
[tailscale]
oauth_client_id_file = "/usr/local/etc/tailnet/oauth_client_id"
oauth_client_secret_file = "/usr/local/etc/tailnet/oauth_client_secret"
state_dir = "/var/db/tailnet"
default_tags = ["tag:server", "tag:tailnet"]

# Global defaults (optional)
[global]
access_log = true
metrics_addr = ":9100"
whois_timeout = "1s"

# Services (at least one required)
[[services]]
name = "wiki"
backend_addr = "127.0.0.1:8080"
whois_enabled = true
```

See `config.example.toml` for a complete configuration reference with all available options.

### 4. Configure OAuth Credentials

Store your Tailscale OAuth credentials securely:

```bash
# Save OAuth client ID
echo "YOUR_CLIENT_ID" > /usr/local/etc/tailnet/oauth_client_id
chmod 600 /usr/local/etc/tailnet/oauth_client_id
chown tailnet:tailnet /usr/local/etc/tailnet/oauth_client_id

# Save OAuth client secret
echo "YOUR_CLIENT_SECRET" > /usr/local/etc/tailnet/oauth_client_secret
chmod 600 /usr/local/etc/tailnet/oauth_client_secret
chown tailnet:tailnet /usr/local/etc/tailnet/oauth_client_secret
```

### 5. Install rc.d Script

```bash
# Copy the rc.d script
install -m 755 tailnet /usr/local/etc/rc.d/tailnet
```

## Service Management

### Enable the Service

Add to `/etc/rc.conf`:

```bash
# Basic configuration
tsbridge_enable="YES"

# Optional: Custom configuration file location
tsbridge_config="/usr/local/etc/tailnet/config.toml"

# Optional: Run as different user/group
tsbridge_user="tailnet"
tsbridge_group="tailnet"

# Optional: Additional command line flags
tsbridge_flags=""

# Optional: Environment variables
tsbridge_env="GOMAXPROCS=4"

# Optional: Process limits (see limits(1))
tsbridge_limits="-n 65535"  # Max file descriptors
```

### Service Commands

```bash
# Start the service
service tailnet start

# Stop the service
service tailnet stop

# Check service status
service tailnet status

# Reload configuration (if supported by tailnet)
service tailnet reload

# Enable service to start at boot
sysrc tsbridge_enable="YES"

# Disable service from starting at boot
sysrc tsbridge_enable="NO"
```

## Monitoring

### View Logs

```bash
# Service logs
tail -f /var/log/tailnet/tailnet.log

# Or use newsyslog for log rotation
```

### Configure Log Rotation

Install the provided newsyslog configuration:

```bash
# Copy the newsyslog configuration
install -m 644 tailnet-newsyslog.conf /usr/local/etc/newsyslog.conf.d/tailnet.conf

# Or if using /etc/newsyslog.conf directly, append the configuration:
cat tailnet-newsyslog.conf >> /etc/newsyslog.conf
```

This will rotate logs daily at midnight, keeping 7 days of compressed logs.

### Check Service Status

```bash
# Check if service is running
service tailnet status

# Check process
ps aux | grep tailnet

# Check network listeners
sockstat -4 -6 | grep tailnet
```

## Security Considerations

### File Permissions

Ensure proper permissions on sensitive files:

```bash
# Configuration files
chmod 644 /usr/local/etc/tailnet/config.toml
chmod 600 /usr/local/etc/tailnet/oauth_client_*

# Directories
chmod 750 /var/run/tailnet
chmod 750 /var/log/tailnet
chmod 750 /var/db/tailnet
```

### Firewall Configuration

If using `pf`, add rules to allow tailnet traffic:

```pf
# /etc/pf.conf
# Allow tailnet metrics (if enabled)
pass in quick on $int_if proto tcp to port 9100

# Tailscale traffic is handled by tailscale itself
```

### Resource Limits

The rc.d script sets appropriate file descriptor limits by default. Additional limits can be configured in `/etc/rc.conf`:

```bash
# Example: Set custom limits
tsbridge_limits="-n 100000 -u 512"  # Max files: 100k, Max processes: 512
```

## Troubleshooting

### Service Won't Start

1. Check configuration syntax:

   ```bash
   /usr/local/bin/tailnet -config /usr/local/etc/tailnet/config.toml -validate
   ```

2. Check logs:

   ```bash
   tail -n 50 /var/log/tailnet/tailnet.log
   ```

3. Verify permissions:

   ```bash
   ls -la /usr/local/etc/tailnet/
   ls -la /var/run/tailnet/
   ls -la /var/log/tailnet/
   ```

4. Run manually for debugging:
   ```bash
   su -m tailnet -c '/usr/local/bin/tailnet -config /usr/local/etc/tailnet/config.toml -verbose'
   ```

### Common Issues

1. **OAuth Authentication Fails**
   - Verify OAuth credentials are correct
   - Check file permissions on credential files
   - Ensure tailnet user can read the files

2. **Port Already in Use**
   - Check for conflicting services: `sockstat -4 -6 | grep :PORT`
   - Adjust service configuration to use different ports

3. **File Descriptor Limits**
   - Increase limits in rc.conf: `tsbridge_limits="-n 100000"`
   - Check system-wide limits: `sysctl kern.maxfiles`

## Jail Deployment

To run tailnet in a FreeBSD jail:

1. Create jail with network access
2. Install tailnet inside the jail
3. Configure as normal, but ensure:
   - Tailscale connectivity works from within the jail
   - Backend services are accessible from the jail network

Example jail configuration in `/etc/jail.conf`:

```
tailnet {
    host.hostname = tailnet.local;
    ip4.addr = "lo0|10.0.0.10/32";
    ip6 = "new";
    exec.start = "/bin/sh /etc/rc";
    exec.stop = "/bin/sh /etc/rc.shutdown";
    mount.devfs;
    persist;
}
```

## Maintenance

### Updating tailnet

1. Download new binary
2. Stop service: `service tailnet stop`
3. Replace binary: `install -m 755 tailnet /usr/local/bin/`
4. Start service: `service tailnet start`

### Backup

Important files to backup:

- `/usr/local/etc/tailnet/` (configuration and credentials)
- `/var/db/tailnet/` (if persistent state is stored)
