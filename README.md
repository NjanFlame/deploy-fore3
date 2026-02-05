# 🌟 XeloraCloud Docker VPS Bot

A powerful Discord bot that creates and manages Docker-based VPS containers with full isolation, persistent storage, and comprehensive monitoring.

## ✨ Features

- **🐳 Full Docker Integration**: Creates isolated VPS containers with custom resource limits
- **💾 Persistent Storage**: Docker volumes ensure data persistence across container restarts
- **🔒 Network Isolation**: Custom Docker networks with subnet isolation for enhanced security
- **🛡️ Enhanced Security**: Privileged containers with proper capability management
- **📊 Real-time Monitoring**: CPU, RAM, disk, and network usage monitoring
- **🔧 Auto-configuration**: Automatic SSH setup with user accounts and services
- **⚡ Multi-OS Support**: Ubuntu, Debian, CentOS, Alpine Linux support
- **🚀 Easy Deployment**: Docker Compose for simple setup and management

## 🚀 Quick Start

### Prerequisites

- Docker 20.10+ 
- Docker Compose 2.0+
- Discord Bot Token
- Linux host with sufficient resources

### Installation

1. **Clone or download the bot files**
```bash
# Ensure you have these files:
# - xcbot.py
# - Dockerfile
# - docker-compose.yml
# - requirements.txt
# - setup.sh
# - .env.example
```

2. **Run the setup script**
```bash
chmod +x setup.sh
./setup.sh
```

3. **Configure your bot**
```bash
# Edit .env file with your Discord credentials
nano .env

# Required values:
DISCORD_TOKEN=your_discord_bot_token_here
MAIN_ADMIN_ID=your_discord_user_id_here
```

4. **Start the bot**
```bash
docker-compose up -d
```

5. **Verify it's running**
```bash
docker-compose logs -f xeloracloud-bot
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DISCORD_TOKEN` | Discord bot token | **Required** |
| `MAIN_ADMIN_ID` | Discord admin user ID | **Required** |
| `VPS_USER_ROLE_ID` | Discord role for VPS users | Auto-created |
| `DOCKER_NETWORK_NAME` | Docker network name | `xeloracloud-network` |
| `CPU_THRESHOLD` | CPU monitoring threshold | `90` |
| `RAM_THRESHOLD` | RAM monitoring threshold | `90` |

### Docker Network Configuration

The bot creates a custom Docker network with:
- **Subnet**: `172.20.0.0/16`
- **Driver**: Bridge with custom isolation
- **Features**: Container-to-container communication, port mapping, network isolation

## 🎮 Discord Commands

### User Commands (No Prefix)
- `ping` - Check bot status and latency
- `myvps` - View your VPS containers
- `manage` - Interactive VPS management (start/stop/SSH)
- `vpsinfo <name>` - Get detailed VPS information
- `help` - Show command help

### Admin Commands (No Prefix)
- `create <ram> <cpu> <disk> @user` - Create new VPS
- `serverstats` - Show server resource usage
- `listall` - List all VPS containers

### Slash Commands
- `/ping` - Bot status check
- `/myvps` - Your VPS dashboard
- `/manage` - VPS management interface

## 🐳 Docker Architecture

### Container Features
- **Resource Limits**: Configurable RAM, CPU, and disk limits
- **Privileged Mode**: Full system access for VPS functionality
- **Persistent Volumes**: User data survives container restarts
- **SSH Access**: Automatic SSH server setup with user accounts
- **Network Isolation**: Each VPS gets isolated network access
- **Auto-restart**: Containers restart automatically on failure

### Volume Management
- **Home Directory**: `/home/vpsuser` mounted to persistent volume
- **Temporary Files**: `/tmp` for ephemeral storage
- **Data Persistence**: User files and configurations preserved
- **Volume Cleanup**: Automatic cleanup of unused volumes

### Network Security
- **Custom Bridge Network**: Isolated from host and other containers
- **Dynamic Port Mapping**: SSH ports dynamically assigned
- **Subnet Isolation**: `172.20.0.0/16` subnet for VPS containers
- **Firewall Ready**: Compatible with host firewall rules

## 🖥️ Supported Operating Systems

| OS | Image | SSH | Package Manager |
|----|-------|-----|----------------|
| Ubuntu 20.04 LTS | `ubuntu:20.04` | ✅ | `apt` |
| Ubuntu 22.04 LTS | `ubuntu:22.04` | ✅ | `apt` |
| Ubuntu 24.04 LTS | `ubuntu:24.04` | ✅ | `apt` |
| Debian 11 | `debian:11` | ✅ | `apt` |
| Debian 12 | `debian:12` | ✅ | `apt` |
| CentOS 7 | `centos:7` | ✅ | `yum` |
| Alpine Linux | `alpine:latest` | ✅ | `apk` |

## 📊 Monitoring & Health Checks

### Bot Health Monitoring
- **Container Health**: Automatic health checks every 30 seconds
- **Resource Monitoring**: Real-time CPU and RAM usage tracking
- **Auto-shutdown**: Stops all VPS if host resources exceed thresholds
- **Docker Integration**: Monitors Docker daemon connectivity

### VPS Health Checks
- **Container Status**: Running/stopped/error state monitoring
- **Resource Usage**: Individual container CPU, RAM, disk tracking
- **SSH Connectivity**: Automatic SSH service health verification
- **Network Connectivity**: Container network access verification

## 🔒 Security Features

### Container Security
- **Capability Management**: Selective capability granting (`SYS_ADMIN`, `NET_ADMIN`)
- **AppArmor**: Unconfined mode for VPS functionality
- **User Isolation**: Dedicated user accounts per VPS
- **Network Isolation**: Separated networks prevent container-to-container attacks

### Bot Security
- **Role-based Access**: Discord role-based VPS management
- **Admin Controls**: Separate admin and user command sets
- **Resource Limits**: Prevents resource exhaustion attacks
- **Error Handling**: Secure error messages without sensitive data exposure

## 🚀 Production Deployment

### System Requirements
- **RAM**: 4GB+ (plus VPS allocations)
- **CPU**: 2+ cores
- **Storage**: 50GB+ SSD recommended
- **Network**: Stable internet connection
- **OS**: Linux (Ubuntu/Debian preferred)

### Performance Tuning
```bash
# Increase Docker daemon limits
echo '{"default-ulimits":{"nofile":{"Hard":65536,"Name":"nofile","Soft":65536}}}' > /etc/docker/daemon.json

# Restart Docker daemon
systemctl restart docker

# Monitor system resources
docker stats
htop
```

### Backup Strategy
```bash
# Backup VPS data volumes
docker run --rm -v xeloracloud_bot-data:/data -v $(pwd):/backup alpine tar czf /backup/vps-backup.tar.gz /data

# Backup bot database
cp data/vps.db backups/vps-$(date +%Y%m%d).db
```

## 🆘 Troubleshooting

### Common Issues

**Docker not found**
```bash
# Install Docker on Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

**Permission denied**
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Logout and login again
```

**VPS creation fails**
```bash
# Check Docker daemon logs
journalctl -u docker.service -f

# Check bot logs
docker-compose logs xeloracloud-bot
```

**Network issues**
```bash
# Recreate Docker network
docker network rm xeloracloud-network
docker-compose down && docker-compose up -d
```

### Log Analysis
```bash
# View bot logs
docker-compose logs -f xeloracloud-bot

# Check container logs
docker logs <container-name>

# Monitor system resources
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Support

- **Documentation**: Check this README for common issues
- **Discord**: Join our support server (if available)
- **Issues**: Report bugs via GitHub issues
- **Feature Requests**: Submit enhancement requests

---

**🌟 XeloraCloud - Powering your Discord VPS infrastructure with Docker! 🌟**