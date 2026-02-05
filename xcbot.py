# bot.py
import discord
from discord.ext import commands
from discord import app_commands
import asyncio
import subprocess
import json
from datetime import datetime
import shlex
import logging
import shutil
import os
from typing import Optional, List, Dict, Any
import threading
import time
import sqlite3

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed, environment variables should be set manually
    pass
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
MAIN_ADMIN_ID = int(os.getenv('MAIN_ADMIN_ID', '1210291131301101618'))
VPS_USER_ROLE_ID = int(os.getenv('VPS_USER_ROLE_ID', '1210291131301101618'))
DOCKER_NETWORK_NAME = os.getenv('DOCKER_NETWORK_NAME', 'xeloracloud-network')

# XeloraCloud Branding Configuration
BRAND_NAME = "XeloraCloud"
BRAND_EMOJI = "🌟"
LOGO_TOKEN = os.getenv('LOGO_TOKEN', 'https://i.imgur.com/xSsIERx.png')  # Default fallback logo

async def initialize_docker_network():
    """Initialize Docker network for containers with enhanced isolation"""
    try:
        # Check if network exists
        network_exists = False
        try:
            await execute_docker(f"docker network inspect {DOCKER_NETWORK_NAME}")
            network_exists = True
            logger.info(f"Using existing Docker network: {DOCKER_NETWORK_NAME}")
        except:
            pass
        
        if not network_exists:
            # Create custom network with isolation and custom subnet
            await execute_docker(f"docker network create --driver bridge --subnet=172.20.0.0/16 --opt com.docker.network.bridge.name=xelora-br0 {DOCKER_NETWORK_NAME}")
            logger.info(f"Created Docker network: {DOCKER_NETWORK_NAME}")
        
        # Cleanup orphaned volumes and networks
        await cleanup_docker_resources()
        
    except Exception as e:
        logger.error(f"Failed to initialize Docker network: {e}")
        logger.warning("Using default bridge network as fallback")

async def cleanup_docker_resources():
    """Cleanup orphaned Docker resources"""
    try:
        # Remove unused volumes
        await execute_docker("docker volume prune -f")
        logger.info("Cleaned up unused Docker volumes")
        
        # Remove unused networks (except our main network)
        networks_output = await execute_docker("docker network ls --format '{{.Name}}'")
        for network in networks_output.split('\n'):
            if network.startswith('xeloracloud-') and network != DOCKER_NETWORK_NAME:
                try:
                    await execute_docker(f"docker network rm {network}")
                    logger.info(f"Removed unused network: {network}")
                except:
                    pass  # Network might be in use
                    
    except Exception as e:
        logger.warning(f"Cleanup failed (non-critical): {e}")

async def create_docker_volume(volume_name, size_gb=None):
    """Create a Docker volume with optional size limit"""
    try:
        if size_gb:
            # Create volume with size limit (requires specific storage driver)
            await execute_docker(f"docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=size={size_gb}g {volume_name}")
        else:
            await execute_docker(f"docker volume create {volume_name}")
        logger.info(f"Created Docker volume: {volume_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to create volume {volume_name}: {e}")
        return False

async def remove_docker_volume(volume_name):
    """Remove a Docker volume safely"""
    try:
        await execute_docker(f"docker volume rm {volume_name}")
        logger.info(f"Removed Docker volume: {volume_name}")
        return True
    except Exception as e:
        logger.warning(f"Failed to remove volume {volume_name}: {e}")
        return False

async def get_container_ssh_port(container_name):
    """Get the dynamically assigned SSH port for a container"""
    try:
        port_info = await execute_docker(f"docker port {container_name} 22")
        if port_info and ":" in port_info:
            return port_info.split(":")[-1].strip()
        return None
    except Exception as e:
        logger.error(f"Failed to get SSH port for {container_name}: {e}")
        return None

# OS Options for VPS Creation (Docker Images)
OS_OPTIONS = [
    {"label": "Ubuntu 20.04 LTS", "value": "ubuntu:20.04"},
    {"label": "Ubuntu 22.04 LTS", "value": "ubuntu:22.04"},
    {"label": "Ubuntu 24.04 LTS", "value": "ubuntu:24.04"},
    {"label": "Debian 10 (Buster)", "value": "debian:10"},
    {"label": "Debian 11 (Bullseye)", "value": "debian:11"},
    {"label": "Debian 12 (Bookworm)", "value": "debian:12"},
    {"label": "CentOS 7", "value": "centos:7"},
    {"label": "Alpine Linux", "value": "alpine:latest"},
]

# Configure logging to file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('xeloracloud_vps_bot')

# Check if docker command is available
if not shutil.which("docker"):
    logger.error("Docker command not found. Please ensure Docker is installed.")
    raise SystemExit("Docker command not found. Please ensure Docker is installed.")

# Database setup
def get_db():
    conn = sqlite3.connect('vps.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS admins (
        user_id TEXT PRIMARY KEY
    )''')
    cur.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (str(MAIN_ADMIN_ID),))

    cur.execute('''CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        container_name TEXT UNIQUE NOT NULL,
        ram TEXT NOT NULL,
        cpu TEXT NOT NULL,
        storage TEXT NOT NULL,
        config TEXT NOT NULL,
        os_version TEXT DEFAULT 'ubuntu:22.04',
        status TEXT DEFAULT 'stopped',
        suspended INTEGER DEFAULT 0,
        whitelisted INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        shared_with TEXT DEFAULT '[]',
        suspension_history TEXT DEFAULT '[]'
    )''')

    # Migration for os_version column
    cur.execute('PRAGMA table_info(vps)')
    info = cur.fetchall()
    columns = [col[1] for col in info]
    if 'os_version' not in columns:
        cur.execute("ALTER TABLE vps ADD COLUMN os_version TEXT DEFAULT 'ubuntu:22.04'")

    cur.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )''')

    settings_init = [
        ('cpu_threshold', '90'),
        ('ram_threshold', '90'),
    ]
    for key, value in settings_init:
        cur.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))

    conn.commit()
    conn.close()

def get_setting(key: str, default: Any = None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key: str, value: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

def get_vps_data() -> Dict[str, List[Dict[str, Any]]]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM vps')
    rows = cur.fetchall()
    conn.close()
    data = {}
    for row in rows:
        user_id = row['user_id']
        if user_id not in data:
            data[user_id] = []
        vps = dict(row)
        vps['shared_with'] = json.loads(vps['shared_with'])
        vps['suspension_history'] = json.loads(vps['suspension_history'])
        vps['suspended'] = bool(vps['suspended'])
        vps['whitelisted'] = bool(vps['whitelisted'])
        vps['os_version'] = vps.get('os_version', 'ubuntu:22.04')
        data[user_id].append(vps)
    return data

def get_admins() -> List[str]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT user_id FROM admins')
    rows = cur.fetchall()
    conn.close()
    return [row['user_id'] for row in rows]

def save_vps_data():
    conn = get_db()
    cur = conn.cursor()
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            shared_json = json.dumps(vps['shared_with'])
            history_json = json.dumps(vps['suspension_history'])
            suspended_int = 1 if vps['suspended'] else 0
            whitelisted_int = 1 if vps.get('whitelisted', False) else 0
            os_ver = vps.get('os_version', 'ubuntu:22.04')
            if 'id' not in vps or vps['id'] is None:
                cur.execute('''INSERT INTO vps (user_id, container_name, ram, cpu, storage, config, os_version, status, suspended, whitelisted, created_at, shared_with, suspension_history)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (user_id, vps['container_name'], vps['ram'], vps['cpu'], vps['storage'], vps['config'],
                             os_ver, vps['status'], suspended_int, whitelisted_int,
                             vps['created_at'], shared_json, history_json))
                vps['id'] = cur.lastrowid
            else:
                cur.execute('''UPDATE vps SET user_id = ?, ram = ?, cpu = ?, storage = ?, config = ?, os_version = ?, status = ?, suspended = ?, whitelisted = ?, shared_with = ?, suspension_history = ?
                               WHERE id = ?''',
                            (user_id, vps['ram'], vps['cpu'], vps['storage'], vps['config'],
                             os_ver, vps['status'], suspended_int, whitelisted_int, shared_json, history_json, vps['id']))
    conn.commit()
    conn.close()

def save_admin_data():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM admins')
    for admin_id in admin_data['admins']:
        cur.execute('INSERT INTO admins (user_id) VALUES (?)', (admin_id,))
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Load data at startup
vps_data = get_vps_data()
admin_data = {'admins': get_admins()}

# Global settings from DB
CPU_THRESHOLD = int(get_setting('cpu_threshold', 90))
RAM_THRESHOLD = int(get_setting('ram_threshold', 90))

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# Resource monitoring settings
resource_monitor_active = True

# Helper function to truncate text to a specific length
def truncate_text(text, max_length=1024):
    if not text:
        return text
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

# Enhanced embed creation functions with modern XeloraCloud branding
def create_embed(title, description="", color=0x2b2d31):
    """Create a modern embed with XeloraCloud branding and dynamic logo support"""
    embed = discord.Embed(
        title=truncate_text(f"{BRAND_EMOJI} {BRAND_NAME} - {title}", 256),
        description=truncate_text(description, 4096),
        color=color,
        timestamp=datetime.now()
    )
    embed.set_thumbnail(url=LOGO_TOKEN)
    embed.set_footer(text=f"{BRAND_NAME} VPS Manager • Powered by Cloud Technology",
                     icon_url=LOGO_TOKEN)
    return embed

def add_field(embed, name, value, inline=False):
    embed.add_field(
        name=truncate_text(f"▸ {name}", 256),
        value=truncate_text(value, 1024),
        inline=inline
    )
    return embed

def create_success_embed(title, description=""):
    return create_embed(title, description, color=0x57f287)  # Modern green

def create_error_embed(title, description=""):
    return create_embed(title, description, color=0xed4245)  # Modern red

def create_info_embed(title, description=""):
    return create_embed(title, description, color=0x5865f2)  # Modern blue

def create_warning_embed(title, description=""):
    return create_embed(title, description, color=0xfee75c)  # Modern yellow

# Admin checks
def is_admin():
    async def predicate(ctx):
        user_id = str(ctx.author.id)
        if user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", []):
            return True
        raise commands.CheckFailure(f"You need admin permissions to use this command. Contact {BRAND_NAME} support.")
    return commands.check(predicate)

def is_main_admin():
    async def predicate(ctx):
        if str(ctx.author.id) == str(MAIN_ADMIN_ID):
            return True
        raise commands.CheckFailure("Only the main admin can use this command.")
    return commands.check(predicate)

# Enhanced Docker command execution with improved timeout handling and retry logic
async def execute_docker(command, timeout=120, retries=3):
    """
    Execute Docker commands with enhanced error handling and retry logic
    """
    last_error = None
    
    for attempt in range(retries):
        try:
            cmd = shlex.split(command)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise asyncio.TimeoutError(f"Command timed out after {timeout} seconds")
            
            if proc.returncode != 0:
                error = stderr.decode().strip() if stderr else "Command failed with no error output"
                # Check for common recoverable errors
                if "network already exists" in error.lower():
                    logger.info(f"Docker network already exists - continuing")
                    return True
                elif "container already exists" in error.lower():
                    logger.info(f"Docker container already exists - continuing")
                    return True
                elif attempt < retries - 1 and ("resource temporarily unavailable" in error.lower() or "device busy" in error.lower()):
                    logger.warning(f"Retryable Docker error (attempt {attempt + 1}/{retries}): {error}")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue
                else:
                    raise Exception(error)
            
            return stdout.decode().strip() if stdout else True
            
        except asyncio.TimeoutError:
            last_error = f"Command timed out after {timeout} seconds"
            if attempt < retries - 1:
                logger.warning(f"Docker command timeout (attempt {attempt + 1}/{retries}): {command}")
                await asyncio.sleep(2 ** attempt)
                continue
            break
        except Exception as e:
            last_error = str(e)
            if attempt < retries - 1 and ("connection refused" in str(e).lower() or "daemon not running" in str(e).lower()):
                logger.warning(f"Docker daemon issue (attempt {attempt + 1}/{retries}): {e}")
                await asyncio.sleep(5)  # Wait for daemon
                continue
            break
    
    logger.error(f"Docker Error after {retries} attempts: {command} - {last_error}")
    raise Exception(last_error)

# Enhanced Docker container configuration and health checks
async def configure_docker_container(container_name):
    """
    Configure Docker container with enhanced setup and health checks
    """
    try:
        # Install essential packages for VPS functionality
        setup_commands = [
            # Update package lists
            f"docker exec {container_name} bash -c 'apt-get update -y || yum update -y || apk update || true'",
            # Install SSH server and essential tools
            f"docker exec {container_name} bash -c 'apt-get install -y openssh-server nano curl wget htop || yum install -y openssh-server nano curl wget htop || apk add openssh nano curl wget htop || true'",
            # Setup SSH
            f"docker exec {container_name} bash -c 'mkdir -p /var/run/sshd && ssh-keygen -A || true'",
            # Create user account
            f"docker exec {container_name} bash -c 'useradd -m -s /bin/bash vpsuser && echo \"vpsuser:xeloracloud123\" | chpasswd || true'",
            # Add user to sudo group
            f"docker exec {container_name} bash -c 'usermod -aG sudo vpsuser || usermod -aG wheel vpsuser || true'",
            # Enable root login (for admin access)
            f"docker exec {container_name} bash -c 'echo \"root:xeloracloud123\" | chpasswd || true'",
            # Configure SSH
            f"docker exec {container_name} bash -c 'sed -i \"s/#PermitRootLogin.*/PermitRootLogin yes/g\" /etc/ssh/sshd_config || true'",
            f"docker exec {container_name} bash -c 'sed -i \"s/#PasswordAuthentication.*/PasswordAuthentication yes/g\" /etc/ssh/sshd_config || true'",
        ]
        
        for cmd in setup_commands:
            try:
                await execute_docker(cmd, timeout=60)
            except Exception as setup_error:
                logger.warning(f"Non-critical setup command failed: {setup_error}")
        
        # Start SSH service
        try:
            await execute_docker(f"docker exec {container_name} bash -c 'service ssh start || systemctl start sshd || /usr/sbin/sshd || true'")
        except Exception as ssh_error:
            logger.warning(f"SSH service start failed (non-critical): {ssh_error}")
        
        logger.info(f"Docker container {container_name} configured successfully")
        
        # Perform health check
        await docker_health_check(container_name)
        
    except Exception as e:
        logger.error(f"Failed to configure Docker container {container_name}: {e}")
        logger.warning(f"Continuing with default configuration for {container_name}. Check logs for details.")

async def docker_health_check(container_name):
    """
    Perform comprehensive health check on Docker container
    """
    try:
        # Check if container is running
        status = await get_container_status(container_name)
        if status != "running":
            logger.warning(f"Container {container_name} is not running: {status}")
            return False
        
        # Check basic connectivity
        result = await execute_docker(f"docker exec {container_name} echo 'Health check'")
        if result != "Health check":
            logger.warning(f"Container {container_name} failed basic connectivity test")
            return False
        
        # Check memory and CPU availability
        try:
            cpu_check = await execute_docker(f"docker exec {container_name} cat /proc/loadavg")
            memory_check = await execute_docker(f"docker exec {container_name} cat /proc/meminfo | grep MemTotal")
            logger.info(f"Container {container_name} health check passed - CPU: OK, Memory: OK")
        except Exception as resource_error:
            logger.warning(f"Resource check failed for {container_name}: {resource_error}")
        
        return True
        
    except Exception as e:
        logger.error(f"Health check failed for container {container_name}: {e}")
        return False

async def get_docker_container_info(container_name):
    """
    Get comprehensive container information
    """
    try:
        # Get container inspect data
        inspect_data = await execute_docker(f"docker inspect {container_name}")
        container_info = json.loads(inspect_data)[0]
        
        # Get container stats
        stats_data = await execute_docker(f"docker stats {container_name} --no-stream --format '{{{{json .}}}}'")
        stats_info = json.loads(stats_data)
        
        return {
            "status": container_info["State"]["Status"],
            "started_at": container_info["State"]["StartedAt"],
            "image": container_info["Config"]["Image"],
            "ip_address": container_info["NetworkSettings"]["Networks"].get(DOCKER_NETWORK_NAME, {}).get("IPAddress", "N/A"),
            "cpu_usage": stats_info.get("CPUPerc", "0%"),
            "memory_usage": stats_info.get("MemUsage", "0B / 0B"),
            "memory_percent": stats_info.get("MemPerc", "0%"),
            "network_io": stats_info.get("NetIO", "0B / 0B"),
            "block_io": stats_info.get("BlockIO", "0B / 0B"),
        }
    except Exception as e:
        logger.error(f"Failed to get container info for {container_name}: {e}")
        return None

# Get or create VPS user role
async def get_or_create_vps_role(guild):
    global VPS_USER_ROLE_ID
    if VPS_USER_ROLE_ID:
        role = guild.get_role(VPS_USER_ROLE_ID)
        if role:
            return role
    role = discord.utils.get(guild.roles, name=f"{BRAND_NAME} VPS User")
    if role:
        VPS_USER_ROLE_ID = role.id
        return role
    try:
        role = await guild.create_role(
            name=f"{BRAND_NAME} VPS User",
            color=discord.Color.from_rgb(88, 101, 242),  # Modern purple/blue
            reason=f"{BRAND_NAME} VPS User role for bot management",
            permissions=discord.Permissions.none()
        )
        VPS_USER_ROLE_ID = role.id
        logger.info(f"Created {BRAND_NAME} VPS User role: {role.name} (ID: {role.id})")
        return role
    except Exception as e:
        logger.error(f"Failed to create {BRAND_NAME} VPS User role: {e}")
        return None

# Host resource monitoring functions
def get_cpu_usage():
    try:
        if shutil.which("mpstat"):
            result = subprocess.run(['mpstat', '1', '1'], capture_output=True, text=True)
            output = result.stdout
            for line in output.split('\n'):
                if 'all' in line and '%' in line:
                    parts = line.split()
                    idle = float(parts[-1])
                    return 100.0 - idle
        else:
            result = subprocess.run(['top', '-bn1'], capture_output=True, text=True)
            output = result.stdout
            for line in output.split('\n'):
                if '%Cpu(s):' in line:
                    parts = line.split()
                    us = float(parts[1])
                    sy = float(parts[3])
                    ni = float(parts[5])
                    id_ = float(parts[7])
                    wa = float(parts[9])
                    hi = float(parts[11])
                    si = float(parts[13])
                    st = float(parts[15])
                    usage = us + sy + ni + wa + hi + si + st
                    return usage
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU usage: {e}")
        return 0.0

def get_ram_usage():
    try:
        result = subprocess.run(['free', '-m'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        if len(lines) > 1:
            mem = lines[1].split()
            total = int(mem[1])
            used = int(mem[2])
            return (used / total * 100) if total > 0 else 0.0
        return 0.0
    except Exception as e:
        logger.error(f"Error getting RAM usage: {e}")
        return 0.0

def resource_monitor():
    global resource_monitor_active
    while resource_monitor_active:
        try:
            cpu_usage = get_cpu_usage()
            ram_usage = get_ram_usage()
            logger.info(f"Current CPU usage: {cpu_usage:.1f}%, RAM usage: {ram_usage:.1f}%")
            if cpu_usage > CPU_THRESHOLD or ram_usage > RAM_THRESHOLD:
                logger.warning(f"Resource usage exceeded thresholds (CPU: {CPU_THRESHOLD}%, RAM: {RAM_THRESHOLD}%). Stopping all VPS.")
                try:
                    # Stop all Docker containers managed by the bot
                    for user_id, vps_list in list(vps_data.items()):
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                try:
                                    subprocess.run(['docker', 'stop', vps['container_name']], check=True)
                                    vps['status'] = 'stopped'
                                except Exception as container_error:
                                    logger.error(f"Failed to stop container {vps['container_name']}: {container_error}")
                    save_vps_data()
                    logger.info("All VPS stopped due to high resource usage")
                except Exception as e:
                    logger.error(f"Error stopping VPS: {e}")
            time.sleep(60)
        except Exception as e:
            logger.error(f"Error in resource monitor: {e}")
            time.sleep(60)

# Start resource monitoring in a separate thread
monitor_thread = threading.Thread(target=resource_monitor, daemon=True)
monitor_thread.start()

# Helper functions for container stats with improved error handling
async def get_container_status(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", container_name, "--format", "{{.State.Status}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            status = stdout.decode().strip().lower()
            # Map Docker status to expected values
            if status == "running":
                return "running"
            elif status in ["exited", "stopped"]:
                return "stopped"
            else:
                return status
        return "unknown"
    except Exception:
        return "unknown"

async def get_container_cpu(container_name):
    usage = await get_container_cpu_pct(container_name)
    return f"{usage:.1f}%"

async def get_container_cpu_pct(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_name, "top", "-bn1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            output = stdout.decode()
            for line in output.splitlines():
                if '%Cpu(s):' in line:
                    parts = line.split()
                    try:
                        us = float(parts[1].replace('%us,', ''))
                        sy = float(parts[2].replace('%sy,', ''))
                        ni = float(parts[3].replace('%ni,', ''))
                        id_ = float(parts[4].replace('%id,', ''))
                        wa = float(parts[5].replace('%wa,', ''))
                        hi = float(parts[6].replace('%hi,', ''))
                        si = float(parts[7].replace('%si,', ''))
                        st = float(parts[8].replace('%st', ''))
                        usage = us + sy + ni + wa + hi + si + st
                        return usage
                    except (ValueError, IndexError):
                        continue
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU for {container_name}: {e}")
        return 0.0

async def get_container_memory(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_name, "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            lines = stdout.decode().splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                total = int(parts[1])
                used = int(parts[2])
                usage_pct = (used / total * 100) if total > 0 else 0
                return f"{used}/{total} MB ({usage_pct:.1f}%)"
        return "Unknown"
    except Exception:
        return "Unknown"

async def get_container_ram_pct(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_name, "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            lines = stdout.decode().splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                total = int(parts[1])
                used = int(parts[2])
                usage_pct = (used / total * 100) if total > 0 else 0
                return usage_pct
        return 0.0
    except Exception as e:
        logger.error(f"Error getting RAM for {container_name}: {e}")
        return 0.0

async def get_container_disk(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_name, "df", "-h", "/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            lines = stdout.decode().splitlines()
            for line in lines:
                if '/dev/' in line and ' /' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        used = parts[2]
                        size = parts[1]
                        perc = parts[4]
                        return f"{used}/{size} ({perc})"
        return "Unknown"
    except Exception:
        return "Unknown"

async def get_container_uptime(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_name, "uptime",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0:
            return stdout.decode().strip() if stdout else "Unknown"
        return "Unknown"
    except Exception:
        return "Unknown"

def get_uptime():
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return "Unknown"

# Bot events
@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    
    # Initialize Docker network
    await initialize_docker_network()
    logger.info(f"Docker network configured: {DOCKER_NETWORK_NAME}")
    
    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        logger.info(f"Synced {len(synced)} slash command(s)")
    except Exception as e:
        logger.error(f"Failed to sync slash commands: {e}")
    
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=f"{BRAND_NAME} Cloud Infrastructure"))
    logger.info(f"{BRAND_NAME} Bot is ready!")

# ================================
# NO-PREFIX COMMANDS SECTION
# ================================

@bot.event
async def on_message(message):
    # Don't respond to bots
    if message.author.bot:
        return
    
    # Process regular prefix commands first
    await bot.process_commands(message)
    
    # Check for no-prefix commands
    content = message.content.strip()
    if not content:
        return
    
    # Split content into words
    words = content.split()
    if not words:
        return
    
    command = words[0].lower()
    args = words[1:] if len(words) > 1 else []
    
    # User commands (no prefix)
    if command == "ping":
        await handle_no_prefix_ping(message)
    elif command == "help":
        await handle_no_prefix_help(message)
    elif command == "myvps":
        await handle_no_prefix_myvps(message)
    elif command == "manage":
        await handle_no_prefix_manage(message)
    elif command == "vpsinfo" and len(args) >= 1:
        await handle_no_prefix_vpsinfo(message, args[0])
    
    # Admin commands (no prefix)
    elif command == "create" and len(args) >= 4:
        await handle_no_prefix_create(message, args)
    elif command == "serverstats":
        await handle_no_prefix_serverstats(message)
    elif command == "listall":
        await handle_no_prefix_listall(message)

# No-prefix command handlers
async def handle_no_prefix_ping(message):
    latency = round(bot.latency * 1000)
    embed = create_success_embed("Pong!", f"{BRAND_NAME} Bot latency: {latency}ms")
    await message.reply(embed=embed)

async def handle_no_prefix_help(message):
    user_id = str(message.author.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    embed = create_info_embed(f"{BRAND_NAME} Bot Commands", f"Available commands for {BRAND_NAME} VPS management")
    
    # No-prefix commands
    user_cmds = "• `ping` - Check bot status\n"
    user_cmds += "• `myvps` - View your VPS list\n"
    user_cmds += "• `manage` - Manage your VPS (start/stop/SSH)\n"
    user_cmds += "• `vpsinfo <name>` - Get detailed VPS info\n"
    user_cmds += "• `help` - Show this help menu"
    add_field(embed, "🚀 No-Prefix Commands", user_cmds, False)
    
    # Slash commands
    slash_cmds = "• `/ping` - Check bot status\n"
    slash_cmds += "• `/myvps` - View your VPS\n"
    slash_cmds += "• `/manage` - Manage VPS\n"
    slash_cmds += "• `/help` - Full command list"
    add_field(embed, "⚡ Slash Commands", slash_cmds, False)
    
    # Legacy prefix commands
    legacy_cmds = "• `!myvps` - View your VPS\n"
    legacy_cmds += "• `!manage` - Manage VPS\n"
    legacy_cmds += "• `!ping` - Bot status"
    add_field(embed, "🔧 Legacy Commands (! prefix)", legacy_cmds, False)
    
    if is_admin:
        admin_cmds = "• `create <ram> <cpu> <disk> @user` - Create VPS\n"
        admin_cmds += "• `serverstats` - Server statistics\n"
        admin_cmds += "• `listall` - List all VPS"
        add_field(embed, "🛡️ Admin Commands (No-Prefix)", admin_cmds, False)
    
    # Tips
    tips = f"💡 **Tips:**\n"
    tips += f"• **No-prefix:** Just type `ping` or `help`\n"
    tips += f"• **Slash commands:** Type `/ping` for autocomplete\n"
    tips += f"• **Legacy:** Use `!ping` for old style\n"
    tips += f"• Contact {BRAND_NAME} admin for VPS creation"
    add_field(embed, "💡 Command Types", tips, False)
    
    await message.reply(embed=embed)

async def handle_no_prefix_myvps(message):
    user_id = str(message.author.id)
    vps_list = vps_data.get(user_id, [])
    if not vps_list:
        embed = create_error_embed("No VPS Found", f"You don't have any {BRAND_NAME} VPS. Contact an admin to create one.")
        add_field(embed, "Quick Actions", f"• Type `manage` - Manage VPS\n• Contact {BRAND_NAME} admin for VPS creation", False)
        await message.reply(embed=embed)
        return
    embed = create_info_embed(f"My {BRAND_NAME} VPS", "")
    text = []
    for i, vps in enumerate(vps_list):
        status = vps.get('status', 'unknown').upper()
        if vps.get('suspended', False):
            status += " (SUSPENDED)"
        if vps.get('whitelisted', False):
            status += " (WHITELISTED)"
        config = vps.get('config', 'Custom')
        text.append(f"**VPS {i+1}:** `{vps['container_name']}` - {status} - {config}")
    add_field(embed, "Your VPS", "\n".join(text), False)
    add_field(embed, "Actions", "Type `manage` to start/stop/reinstall", False)
    await message.reply(embed=embed)

async def handle_no_prefix_manage(message):
    user_id = str(message.author.id)
    vps_list = vps_data.get(user_id, [])
    if not vps_list:
        embed = create_error_embed("No VPS Found", f"You don't have any {BRAND_NAME} VPS. Contact an admin to create one.")
        await message.reply(embed=embed)
        return
    view = ManageView(user_id, vps_list, is_admin=str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID))
    embed = await view.get_initial_embed()
    await message.reply(embed=embed, view=view)

async def handle_no_prefix_vpsinfo(message, vps_name):
    user_id = str(message.author.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    # Find VPS
    found_vps = None
    owner_id = None
    
    for uid, vps_list in vps_data.items():
        for vps in vps_list:
            if vps['container_name'] == vps_name:
                if uid == user_id or is_admin:
                    found_vps = vps
                    owner_id = uid
                    break
        if found_vps:
            break
    
    if not found_vps:
        await message.reply(embed=create_error_embed("VPS Not Found", f"No VPS found with name `{vps_name}` or you don't have access."))
        return
    
    # Get live stats
    container_name = found_vps['container_name']
    status = await get_container_status(container_name)
    cpu_usage = await get_container_cpu(container_name)
    memory_usage = await get_container_memory(container_name)
    disk_usage = await get_container_disk(container_name)
    uptime = await get_container_uptime(container_name)
    
    # Create info embed
    embed = create_info_embed(f"{BRAND_NAME} VPS Information", f"Details for `{container_name}`")
    
    # Basic info
    basic_info = f"**Container:** `{container_name}`\n"
    basic_info += f"**Status:** `{status.upper()}`\n"
    basic_info += f"**Configuration:** {found_vps.get('config', 'Custom')}\n"
    basic_info += f"**OS:** {found_vps.get('os_version', 'ubuntu:22.04')}\n"
    basic_info += f"**Created:** {found_vps.get('created_at', 'Unknown')[:10]}"
    add_field(embed, "📋 Basic Info", basic_info, False)
    
    # Resources
    resource_info = f"**RAM:** {found_vps['ram']}\n"
    resource_info += f"**CPU:** {found_vps['cpu']} Cores\n"
    resource_info += f"**Storage:** {found_vps['storage']}"
    add_field(embed, "🔧 Allocated Resources", resource_info, True)
    
    # Live stats
    live_stats = f"**CPU Usage:** {cpu_usage}\n"
    live_stats += f"**Memory:** {memory_usage}\n"
    live_stats += f"**Disk:** {disk_usage}\n"
    live_stats += f"**Uptime:** {uptime}"
    add_field(embed, "📊 Live Stats", live_stats, True)
    
    # Status indicators
    status_info = ""
    if found_vps.get('suspended', False):
        status_info += "⚠️ **SUSPENDED**\n"
    if found_vps.get('whitelisted', False):
        status_info += "✅ **WHITELISTED**\n"
    if not status_info:
        status_info = "✅ **ACTIVE**"
    add_field(embed, "🚦 Status", status_info, True)
    
    await message.reply(embed=embed)

async def handle_no_prefix_create(message, args):
    user_id = str(message.author.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    if not is_admin:
        await message.reply(embed=create_error_embed("Access Denied", f"You need admin permissions. Contact {BRAND_NAME} support."))
        return
    
    try:
        ram = int(args[0])
        cpu = int(args[1]) 
        disk = int(args[2])
        
        # Parse user mention
        user_mention = args[3]
        if user_mention.startswith('<@') and user_mention.endswith('>'):
            # Extract user ID from mention
            user_id_str = user_mention[2:-1]
            if user_id_str.startswith('!'):
                user_id_str = user_id_str[1:]
            try:
                user = await bot.fetch_user(int(user_id_str))
                # Convert to member if in guild
                if message.guild:
                    user = message.guild.get_member(user.id) or user
            except:
                await message.reply(embed=create_error_embed("Invalid User", "Could not find that user."))
                return
        else:
            await message.reply(embed=create_error_embed("Invalid Format", "Usage: `create <ram> <cpu> <disk> @user`"))
            return
        
    except (ValueError, IndexError):
        await message.reply(embed=create_error_embed("Invalid Format", "Usage: `create <ram> <cpu> <disk> @user`\nExample: `create 8 2 20 @username`"))
        return
    
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await message.reply(embed=create_error_embed("Invalid Specs", "RAM, CPU, and Disk must be positive integers."))
        return
    
    embed = create_info_embed("VPS Creation", f"Creating VPS for {user.mention if hasattr(user, 'mention') else user.name} with {ram}GB RAM, {cpu} CPU cores, {disk}GB Disk.\nSelect OS below.")
    
    # Create a fake context for OSSelectView
    class FakeContext:
        def __init__(self, message):
            self.author = message.author
            self.send = message.reply
            self.guild = message.guild
    
    fake_ctx = FakeContext(message)
    view = OSSelectView(ram, cpu, disk, user, fake_ctx)
    await message.reply(embed=embed, view=view)

async def handle_no_prefix_serverstats(message):
    user_id = str(message.author.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    if not is_admin:
        await message.reply(embed=create_error_embed("Access Denied", f"You need admin permissions. Contact {BRAND_NAME} support."))
        return
    
    # Get server stats
    total_vps = sum(len(vps_list) for vps_list in vps_data.values())
    active_vps = 0
    suspended_vps = 0
    
    for vps_list in vps_data.values():
        for vps in vps_list:
            if vps.get('status') == 'running':
                active_vps += 1
            if vps.get('suspended'):
                suspended_vps += 1
    
    cpu_usage = get_cpu_usage()
    ram_usage = get_ram_usage()
    uptime = get_uptime()
    
    embed = create_info_embed(f"{BRAND_NAME} Server Statistics", "Current server status and resource usage")
    
    # VPS Stats
    vps_stats = f"**Total VPS:** {total_vps}\n"
    vps_stats += f"**Active VPS:** {active_vps}\n"
    vps_stats += f"**Suspended VPS:** {suspended_vps}\n"
    vps_stats += f"**Users:** {len(vps_data)}"
    add_field(embed, "📊 VPS Statistics", vps_stats, True)
    
    # Resource usage
    resource_stats = f"**CPU Usage:** {cpu_usage:.1f}%\n"
    resource_stats += f"**RAM Usage:** {ram_usage:.1f}%\n"
    resource_stats += f"**CPU Threshold:** {CPU_THRESHOLD}%\n"
    resource_stats += f"**RAM Threshold:** {RAM_THRESHOLD}%"
    add_field(embed, "🔧 Host Resources", resource_stats, True)
    
    # System info
    system_info = f"**Uptime:** {uptime}\n"
    system_info += f"**Docker Network:** {DOCKER_NETWORK_NAME}\n"
    system_info += f"**Monitor Active:** {'✅ Yes' if resource_monitor_active else '❌ No'}"
    add_field(embed, "🖥️ System Info", system_info, False)
    
    await message.reply(embed=embed)

async def handle_no_prefix_listall(message):
    user_id = str(message.author.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    if not is_admin:
        await message.reply(embed=create_error_embed("Access Denied", f"You need admin permissions. Contact {BRAND_NAME} support."))
        return
    
    if not vps_data:
        await message.reply(embed=create_error_embed("No VPS Found", "No VPS are currently registered."))
        return
    
    embed = create_info_embed(f"{BRAND_NAME} All VPS", "Complete list of all VPS on the server")
    
    for user_id, vps_list in vps_data.items():
        try:
            user = await bot.fetch_user(int(user_id))
            username = f"{user.display_name} ({user.name})"
        except:
            username = f"User ID: {user_id}"
        
        user_vps = []
        for i, vps in enumerate(vps_list):
            status = vps.get('status', 'unknown').upper()
            if vps.get('suspended'):
                status += " (SUSPENDED)"
            if vps.get('whitelisted'):
                status += " (WHITELISTED)"
            user_vps.append(f"VPS {i+1}: `{vps['container_name']}` - {status}")
        
        add_field(embed, f"👤 {username}", "\n".join(user_vps), False)
    
    await message.reply(embed=embed)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=create_error_embed("Missing Argument", "Please check command usage with `!help`."))
    elif isinstance(error, commands.BadArgument):
        await ctx.send(embed=create_error_embed("Invalid Argument", "Please check your input and try again."))
    elif isinstance(error, commands.CheckFailure):
        error_msg = str(error) if str(error) else f"You need admin permissions for this command. Contact {BRAND_NAME} support."
        await ctx.send(embed=create_error_embed("Access Denied", error_msg))
    elif isinstance(error, discord.NotFound):
        await ctx.send(embed=create_error_embed("Error", "The requested resource was not found. Please try again."))
    else:
        logger.error(f"Command error: {error}")
        await ctx.send(embed=create_error_embed("System Error", f"An unexpected error occurred. {BRAND_NAME} support has been notified."))

# Bot commands
@bot.command(name='ping')
async def ping(ctx):
    latency = round(bot.latency * 1000)
    embed = create_success_embed("Pong!", f"{BRAND_NAME} Bot latency: {latency}ms")
    await ctx.send(embed=embed)

@bot.command(name='uptime')
async def uptime(ctx):
    up = get_uptime()
    embed = create_info_embed("Host Uptime", up)
    await ctx.send(embed=embed)

@bot.command(name='thresholds')
@is_admin()
async def thresholds(ctx):
    embed = create_info_embed("Resource Thresholds", f"**CPU:** {CPU_THRESHOLD}%\n**RAM:** {RAM_THRESHOLD}%")
    await ctx.send(embed=embed)

@bot.command(name='set-threshold')
@is_admin()
async def set_threshold(ctx, cpu: int, ram: int):
    global CPU_THRESHOLD, RAM_THRESHOLD
    if cpu < 0 or ram < 0:
        await ctx.send(embed=create_error_embed("Invalid Thresholds", "Thresholds must be non-negative."))
        return
    CPU_THRESHOLD = cpu
    RAM_THRESHOLD = ram
    set_setting('cpu_threshold', str(cpu))
    set_setting('ram_threshold', str(ram))
    embed = create_success_embed("Thresholds Updated", f"**CPU:** {cpu}%\n**RAM:** {ram}%")
    await ctx.send(embed=embed)

@bot.command(name='set-status')
@is_admin()
async def set_status(ctx, activity_type: str, *, name: str):
    types = {
        'playing': discord.ActivityType.playing,
        'watching': discord.ActivityType.watching,
        'listening': discord.ActivityType.listening,
        'streaming': discord.ActivityType.streaming,
    }
    if activity_type.lower() not in types:
        await ctx.send(embed=create_error_embed("Invalid Type", "Valid types: playing, watching, listening, streaming"))
        return
    await bot.change_presence(activity=discord.Activity(type=types[activity_type.lower()], name=name))
    embed = create_success_embed("Status Updated", f"Set to {activity_type}: {name}")
    await ctx.send(embed=embed)

@bot.command(name='myvps')
async def my_vps(ctx):
    user_id = str(ctx.author.id)
    vps_list = vps_data.get(user_id, [])
    if not vps_list:
        embed = create_error_embed("No VPS Found", f"You don't have any {BRAND_NAME} VPS. Contact an admin to create one.")
        add_field(embed, "Quick Actions", f"• `!manage` - Manage VPS\n• Contact {BRAND_NAME} admin for VPS creation", False)
        await ctx.send(embed=embed)
        return
    embed = create_info_embed(f"My {BRAND_NAME} VPS", "")
    text = []
    for i, vps in enumerate(vps_list):
        status = vps.get('status', 'unknown').upper()
        if vps.get('suspended', False):
            status += " (SUSPENDED)"
        if vps.get('whitelisted', False):
            status += " (WHITELISTED)"
        config = vps.get('config', 'Custom')
        text.append(f"**VPS {i+1}:** `{vps['container_name']}` - {status} - {config}")
    add_field(embed, "Your VPS", "\n".join(text), False)
    add_field(embed, "Actions", "Use `!manage` to start/stop/reinstall", False)
    await ctx.send(embed=embed)

@bot.command(name='docker-list')
@is_admin()
async def docker_list(ctx):
    try:
        result = await execute_docker("docker ps -a")
        embed = create_info_embed(f"{BRAND_NAME} Docker Containers List", result)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Error", str(e)))

class OSSelectView(discord.ui.View):
    def __init__(self, ram: int, cpu: int, disk: int, user: discord.Member, ctx):
        super().__init__(timeout=300)
        self.ram = ram
        self.cpu = cpu
        self.disk = disk
        self.user = user
        self.ctx = ctx
        self.select = discord.ui.Select(
            placeholder="Select an OS for the VPS",
            options=[discord.SelectOption(label=o["label"], value=o["value"]) for o in OS_OPTIONS]
        )
        self.select.callback = self.select_os
        self.add_item(self.select)

    async def select_os(self, interaction: discord.Interaction):
        if str(interaction.user.id) != str(self.ctx.author.id):
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "Only the command author can select."), ephemeral=True)
            return
        os_version = self.select.values[0]
        self.select.disabled = True
        creating_embed = create_info_embed("Creating VPS", f"Deploying {os_version} VPS for {self.user.mention}...")
        await interaction.response.edit_message(embed=creating_embed, view=self)
        user_id = str(self.user.id)
        if user_id not in vps_data:
            vps_data[user_id] = []
        vps_count = len(vps_data[user_id]) + 1
        container_name = f"xeloracloud-vps-{user_id}-{vps_count}"
        ram_mb = self.ram * 1024
        try:
            # Create Docker volume for persistent storage
            volume_name = f"{container_name}-data"
            await execute_docker(f"docker volume create {volume_name}")
            
            # Create Docker container with enhanced configuration
            docker_cmd = [
                "docker", "run", "-d",
                "--name", container_name,
                "--network", DOCKER_NETWORK_NAME,
                f"--memory={ram_mb}m",
                f"--cpus={self.cpu}",
                "--privileged",
                "--restart=unless-stopped",  # Auto-restart policy
                "-v", f"{volume_name}:/home/vpsuser",  # Persistent home directory
                "-v", "/tmp",  # Temp directory
                "--security-opt", "apparmor=unconfined",  # Required for some VPS operations
                "--cap-add=SYS_ADMIN",  # System administration capabilities
                "--cap-add=NET_ADMIN",  # Network administration capabilities
                "-p", "0:22",  # Dynamic SSH port mapping
                os_version,
                "/bin/bash", "-c", "while true; do sleep 30; done"  # Keep container running
            ]
            await execute_docker(" ".join(shlex.quote(arg) for arg in docker_cmd))
            await configure_docker_container(container_name)
            config_str = f"{self.ram}GB RAM / {self.cpu} CPU / {self.disk}GB Disk"
            # Get SSH port for the container
            ssh_port = await get_container_ssh_port(container_name)
            
            vps_info = {
                "container_name": container_name,
                "ram": f"{self.ram}GB",
                "cpu": str(self.cpu),
                "storage": f"{self.disk}GB",
                "config": config_str,
                "os_version": os_version,
                "status": "running",
                "suspended": False,
                "whitelisted": False,
                "suspension_history": [],
                "created_at": datetime.now().isoformat(),
                "shared_with": [],
                "ssh_port": ssh_port,
                "volume_name": volume_name,
                "id": None
            }
            vps_data[user_id].append(vps_info)
            save_vps_data()
            if self.ctx.guild:
                vps_role = await get_or_create_vps_role(self.ctx.guild)
                if vps_role:
                    try:
                        await self.user.add_roles(vps_role, reason=f"{BRAND_NAME} VPS ownership granted")
                    except discord.Forbidden:
                        logger.warning(f"Failed to assign {BRAND_NAME} VPS role to {self.user.name}")
            success_embed = create_success_embed(f"{BRAND_NAME} VPS Created Successfully")
            add_field(success_embed, "Owner", self.user.mention, True)
            add_field(success_embed, "VPS ID", f"#{vps_count}", True)
            add_field(success_embed, "Container", f"`{container_name}`", True)
            add_field(success_embed, "Resources", f"**RAM:** {self.ram}GB\n**CPU:** {self.cpu} Cores\n**Storage:** {self.disk}GB", False)
            add_field(success_embed, "OS", os_version, True)
            add_field(success_embed, "Features", "Privileged Access, Network Isolation, Resource Management", False)
            add_field(success_embed, "Access Note", "Container is running and ready for use. Use SSH or management commands to access.", False)
            await interaction.followup.send(embed=success_embed)
            dm_embed = create_success_embed(f"{BRAND_NAME} VPS Created!", f"Your VPS has been successfully deployed by an admin!")
            add_field(dm_embed, "VPS Details", f"**VPS ID:** #{vps_count}\n**Container Name:** `{container_name}`\n**Configuration:** {config_str}\n**Status:** Running\n**OS:** {os_version}\n**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", False)
            add_field(dm_embed, "Management", f"• Use `!manage` to start/stop/reinstall your {BRAND_NAME} VPS\n• Use `!manage` → SSH for terminal access\n• Contact {BRAND_NAME} admin for upgrades or issues", False)
            add_field(dm_embed, "Important Notes", "• Full root access via SSH\n• Docker-ready with nesting and privileged mode\n• Back up your data regularly", False)
            try:
                await self.user.send(embed=dm_embed)
            except discord.Forbidden:
                await self.ctx.send(embed=create_info_embed("Notification Failed", f"Couldn't send DM to {self.user.mention}. Please ensure DMs are enabled."))
        except Exception as e:
            error_embed = create_error_embed("Creation Failed", f"Error: {str(e)}")
            await interaction.followup.send(embed=error_embed)

@bot.command(name='create')
@is_admin()
async def create_vps(ctx, ram: int, cpu: int, disk: int, user: discord.Member):
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await ctx.send(embed=create_error_embed("Invalid Specs", "RAM, CPU, and Disk must be positive integers."))
        return
    embed = create_info_embed("VPS Creation", f"Creating VPS for {user.mention} with {ram}GB RAM, {cpu} CPU cores, {disk}GB Disk.\nSelect OS below.")
    view = OSSelectView(ram, cpu, disk, user, ctx)
    await ctx.send(embed=embed, view=view)

class ManageView(discord.ui.View):
    def __init__(self, user_id, vps_list, is_shared=False, owner_id=None, is_admin=False, actual_index: Optional[int] = None):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.vps_list = vps_list[:]
        self.selected_index = None
        self.is_shared = is_shared
        self.owner_id = owner_id or user_id
        self.is_admin = is_admin
        self.actual_index = actual_index
        self.indices = list(range(len(vps_list)))
        if self.is_shared and self.actual_index is None:
            raise ValueError("actual_index required for shared views")
        if len(vps_list) > 1:
            options = [
                discord.SelectOption(
                    label=f"{BRAND_NAME} VPS {i+1} ({v.get('config', 'Custom')})",
                    description=f"Status: {v.get('status', 'unknown')}",
                    value=str(i)
                ) for i, v in enumerate(vps_list)
            ]
            self.select = discord.ui.Select(placeholder=f"Select a {BRAND_NAME} VPS to manage", options=options)
            self.select.callback = self.select_vps
            self.add_item(self.select)
            self.initial_embed = create_embed(f"{BRAND_NAME} VPS Management", "Select a VPS from the dropdown menu below.", 0x2b2d31)
            add_field(self.initial_embed, "Available VPS", "\n".join([f"**VPS {i+1}:** `{v['container_name']}` - Status: `{v.get('status', 'unknown').upper()}`" for i, v in enumerate(vps_list)]), False)
        else:
            self.selected_index = 0
            self.initial_embed = None
            self.add_action_buttons()

    async def get_initial_embed(self):
        if self.initial_embed is not None:
            return self.initial_embed
        self.initial_embed = await self.create_vps_embed(self.selected_index)
        return self.initial_embed

    async def create_vps_embed(self, index):
        vps = self.vps_list[index]
        status = vps.get('status', 'unknown')
        suspended = vps.get('suspended', False)
        whitelisted = vps.get('whitelisted', False)
        status_color = 0x00ff88 if status == 'running' and not suspended else 0xffaa00 if suspended else 0xff3366
        container_name = vps['container_name']
        lxc_status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        uptime = await get_container_uptime(container_name)
        status_text = f"{lxc_status.upper()}"
        if suspended:
            status_text += " (SUSPENDED)"
        if whitelisted:
            status_text += " (WHITELISTED)"
        owner_text = ""
        if self.is_admin and self.owner_id != self.user_id:
            try:
                owner_user = await bot.fetch_user(int(self.owner_id))
                owner_text = f"\n**Owner:** {owner_user.mention}"
            except:
                owner_text = f"\n**Owner ID:** {self.owner_id}"
        embed = create_embed(
            f"{BRAND_NAME} VPS Management - VPS {index + 1}",
            f"Managing container: `{container_name}`{owner_text}",
            status_color
        )
        resource_info = f"**Configuration:** {vps.get('config', 'Custom')}\n"
        resource_info += f"**Status:** `{status_text}`\n"
        resource_info += f"**RAM:** {vps['ram']}\n"
        resource_info += f"**CPU:** {vps['cpu']} Cores\n"
        resource_info += f"**Storage:** {vps['storage']}\n"
        resource_info += f"**OS:** {vps.get('os_version', 'ubuntu:22.04')}\n"
        resource_info += f"**Uptime:** {uptime}"
        add_field(embed, "📊 Allocated Resources", resource_info, False)
        if suspended:
            add_field(embed, "⚠️ Suspended", f"This {BRAND_NAME} VPS is suspended. Contact an admin to unsuspend.", False)
        if whitelisted:
            add_field(embed, "✅ Whitelisted", "This VPS is exempt from auto-suspension.", False)
        live_stats = f"**CPU Usage:** {cpu_usage}\n**Memory:** {memory_usage}\n**Disk:** {disk_usage}"
        add_field(embed, "📈 Live Usage", live_stats, False)
        add_field(embed, "🎮 Controls", f"Use the buttons below to manage your {BRAND_NAME} VPS", False)
        return embed

    def add_action_buttons(self):
        if not self.is_shared and not self.is_admin:
            reinstall_button = discord.ui.Button(label="🔄 Reinstall", style=discord.ButtonStyle.danger)
            reinstall_button.callback = lambda inter: self.action_callback(inter, 'reinstall')
            self.add_item(reinstall_button)
        start_button = discord.ui.Button(label="▶ Start", style=discord.ButtonStyle.success)
        start_button.callback = lambda inter: self.action_callback(inter, 'start')
        stop_button = discord.ui.Button(label="⏸ Stop", style=discord.ButtonStyle.secondary)
        stop_button.callback = lambda inter: self.action_callback(inter, 'stop')
        ssh_button = discord.ui.Button(label="🔑 SSH", style=discord.ButtonStyle.primary)
        ssh_button.callback = lambda inter: self.action_callback(inter, 'tmate')
        stats_button = discord.ui.Button(label="📊 Stats", style=discord.ButtonStyle.secondary)
        stats_button.callback = lambda inter: self.action_callback(inter, 'stats')
        self.add_item(start_button)
        self.add_item(stop_button)
        self.add_item(ssh_button)
        self.add_item(stats_button)

    async def select_vps(self, interaction: discord.Interaction):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", f"This is not your {BRAND_NAME} VPS!"), ephemeral=True)
            return
        self.selected_index = int(self.select.values[0])
        new_embed = await self.create_vps_embed(self.selected_index)
        self.clear_items()
        self.add_action_buttons()
        await interaction.response.edit_message(embed=new_embed, view=self)

    async def action_callback(self, interaction: discord.Interaction, action: str):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", f"This is not your {BRAND_NAME} VPS!"), ephemeral=True)
            return
        if self.selected_index is None:
            await interaction.response.send_message(embed=create_error_embed("No VPS Selected", "Please select a VPS first."), ephemeral=True)
            return
        actual_idx = self.actual_index if self.is_shared else self.indices[self.selected_index]
        target_vps = vps_data[self.owner_id][actual_idx]
        suspended = target_vps.get('suspended', False)
        if suspended and not self.is_admin and action != 'stats':
            await interaction.response.send_message(embed=create_error_embed("Access Denied", f"This {BRAND_NAME} VPS is suspended. Contact an admin to unsuspend."), ephemeral=True)
            return
        container_name = target_vps["container_name"]
        if action == 'stats':
            status = await get_container_status(container_name)
            cpu_usage = await get_container_cpu(container_name)
            memory_usage = await get_container_memory(container_name)
            disk_usage = await get_container_disk(container_name)
            uptime = await get_container_uptime(container_name)
            stats_embed = create_info_embed(f"📈 {BRAND_NAME} Live Statistics", f"Real-time stats for `{container_name}`")
            add_field(stats_embed, "Status", f"`{status.upper()}`", True)
            add_field(stats_embed, "CPU", cpu_usage, True)
            add_field(stats_embed, "Memory", memory_usage, True)
            add_field(stats_embed, "Disk", disk_usage, True)
            add_field(stats_embed, "Uptime", uptime, True)
            await interaction.response.send_message(embed=stats_embed, ephemeral=True)
            return
        if action == 'reinstall':
            if self.is_shared or self.is_admin:
                await interaction.response.send_message(embed=create_error_embed("Access Denied", f"Only the {BRAND_NAME} VPS owner can reinstall!"), ephemeral=True)
                return
            if suspended:
                await interaction.response.send_message(embed=create_error_embed("Cannot Reinstall", f"Unsuspend the {BRAND_NAME} VPS first."), ephemeral=True)
                return
            os_version = target_vps.get('os_version', 'ubuntu:22.04')
            confirm_embed = create_warning_embed(f"{BRAND_NAME} Reinstall Warning",
                f"⚠️ **WARNING:** This will erase all data on VPS `{container_name}` and reinstall {os_version}.\n\n"
                f"This action cannot be undone. Continue?")
            class ConfirmView(discord.ui.View):
                def __init__(self, parent_view, container_name, owner_id, actual_idx):
                    super().__init__(timeout=60)
                    self.parent_view = parent_view
                    self.container_name = container_name
                    self.owner_id = owner_id
                    self.actual_idx = actual_idx

                @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
                async def confirm(self, inter: discord.Interaction, item: discord.ui.Button):
                    await inter.response.defer(ephemeral=True)
                    try:
                        await inter.followup.send(embed=create_info_embed("Deleting Container", f"Forcefully removing container `{self.container_name}`..."), ephemeral=True)
                        await execute_lxc(f"lxc delete {self.container_name} --force")
                        await inter.followup.send(embed=create_info_embed("Recreating Container", f"Creating new {BRAND_NAME} container `{self.container_name}`..."), ephemeral=True)
                        target_vps = vps_data[self.owner_id][self.actual_idx]
                        original_ram = target_vps["ram"]
                        original_cpu = target_vps["cpu"]
                        original_storage = target_vps["storage"]
                        ram_gb = int(original_ram.replace("GB", ""))
                        ram_mb = ram_gb * 1024
                        storage_gb = int(original_storage.replace("GB", ""))
                        os_version = target_vps.get('os_version', 'ubuntu:22.04')
                        await execute_lxc(f"lxc init {os_version} {self.container_name} -s {DEFAULT_STORAGE_POOL}")
                        await execute_lxc(f"lxc config set {self.container_name} limits.memory {ram_mb}MB")
                        await execute_lxc(f"lxc config set {self.container_name} limits.cpu {original_cpu}")
                        await execute_lxc(f"lxc config device set {self.container_name} root size={storage_gb}GB")
                        await apply_advanced_permissions(self.container_name)
                        await execute_lxc(f"lxc start {self.container_name}")
                        target_vps["status"] = "running"
                        target_vps["suspended"] = False
                        target_vps["created_at"] = datetime.now().isoformat()
                        config_str = f"{ram_gb}GB RAM / {original_cpu} CPU / {storage_gb}GB Disk"
                        target_vps["config"] = config_str
                        save_vps_data()
                        await inter.followup.send(embed=create_success_embed("Reinstall Complete", f"{BRAND_NAME} VPS `{self.container_name}` has been successfully reinstalled!"), ephemeral=True)
                        new_embed = await self.parent_view.create_vps_embed(self.parent_view.selected_index)
                        await inter.followup.send(embed=new_embed, view=self.parent_view, ephemeral=True)
                    except Exception as e:
                        await inter.followup.send(embed=create_error_embed("Reinstall Failed", f"Error: {str(e)}"), ephemeral=True)

                @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
                async def cancel(self, inter: discord.Interaction, item: discord.ui.Button):
                    new_embed = await self.parent_view.create_vps_embed(self.parent_view.selected_index)
                    await inter.response.edit_message(embed=new_embed, view=self.parent_view)
            await interaction.response.send_message(embed=confirm_embed, view=ConfirmView(self, container_name, self.owner_id, actual_idx), ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        suspended = target_vps.get('suspended', False)
        if suspended:
            target_vps['suspended'] = False
            save_vps_data()
        if action == 'start':
            try:
                await execute_lxc(f"lxc start {container_name}")
                target_vps["status"] = "running"
                save_vps_data()
                await interaction.followup.send(embed=create_success_embed("VPS Started", f"{BRAND_NAME} VPS `{container_name}` is now running!"), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Start Failed", str(e)), ephemeral=True)
        elif action == 'stop':
            try:
                await execute_lxc(f"lxc stop {container_name}", timeout=120)
                target_vps["status"] = "stopped"
                save_vps_data()
                await interaction.followup.send(embed=create_success_embed("VPS Stopped", f"{BRAND_NAME} VPS `{container_name}` has been stopped!"), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Stop Failed", str(e)), ephemeral=True)
        elif action == 'tmate':
            if suspended:
                await interaction.followup.send(embed=create_error_embed("Access Denied", f"Cannot access suspended {BRAND_NAME} VPS."), ephemeral=True)
                return
            await interaction.followup.send(embed=create_info_embed("SSH Access", f"Generating {BRAND_NAME} SSH connection..."), ephemeral=True)
            try:
                check_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "which", "tmate",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await check_proc.communicate()
                if check_proc.returncode != 0:
                    await interaction.followup.send(embed=create_info_embed("Installing SSH", "Installing tmate..."), ephemeral=True)
                    await execute_lxc(f"lxc exec {container_name} -- apt-get update -y")
                    await execute_lxc(f"lxc exec {container_name} -- apt-get install tmate -y")
                    await interaction.followup.send(embed=create_success_embed("Installed", f"{BRAND_NAME} SSH service installed!"), ephemeral=True)
                session_name = f"xeloracloud-session-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                await execute_lxc(f"lxc exec {container_name} -- tmate -S /tmp/{session_name}.sock new-session -d")
                await asyncio.sleep(3)
                ssh_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "tmate", "-S", f"/tmp/{session_name}.sock", "display", "-p", "#{tmate_ssh}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await ssh_proc.communicate()
                ssh_url = stdout.decode().strip() if stdout else None
                if ssh_url:
                    try:
                        ssh_embed = create_embed(f"🔐 {BRAND_NAME} SSH Access", f"SSH connection for VPS `{container_name}`:", 0x57f287)
                        add_field(ssh_embed, "Command", f"```{ssh_url}```", False)
                        add_field(ssh_embed, "⚠️ Security", "This link is temporary. Do not share it.", False)
                        add_field(ssh_embed, "📝 Session", f"Session ID: {session_name}", False)
                        await interaction.user.send(embed=ssh_embed)
                        await interaction.followup.send(embed=create_success_embed("SSH Sent", f"Check your DMs for {BRAND_NAME} SSH link! Session: {session_name}"), ephemeral=True)
                    except discord.Forbidden:
                        await interaction.followup.send(embed=create_error_embed("DM Failed", f"Enable DMs to receive {BRAND_NAME} SSH link!"), ephemeral=True)
                else:
                    error_msg = stderr.decode().strip() if stderr else "Unknown error"
                    await interaction.followup.send(embed=create_error_embed("SSH Failed", error_msg), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("SSH Error", str(e)), ephemeral=True)
        new_embed = await self.create_vps_embed(self.selected_index)
        await interaction.message.edit(embed=new_embed, view=self)

@bot.command(name='manage')
async def manage_vps(ctx, user: discord.Member = None):
    if user:
        user_id_check = str(ctx.author.id)
        if user_id_check != str(MAIN_ADMIN_ID) and user_id_check not in admin_data.get("admins", []):
            await ctx.send(embed=create_error_embed("Access Denied", f"Only {BRAND_NAME} admins can manage other users' VPS."))
            return
        user_id = str(user.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            await ctx.send(embed=create_error_embed("No VPS Found", f"{user.mention} doesn't have any {BRAND_NAME} VPS."))
            return
        view = ManageView(str(ctx.author.id), vps_list, is_admin=True, owner_id=user_id)
        await ctx.send(embed=create_info_embed(f"Managing {user.name}'s {BRAND_NAME} VPS", f"Managing VPS for {user.mention}"), view=view)
    else:
        user_id = str(ctx.author.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            embed = create_error_embed("No VPS Found", f"You don't have any {BRAND_NAME} VPS. Contact an admin to create one.")
            add_field(embed, "Quick Actions", f"• `!manage` - Manage VPS\n• Contact {BRAND_NAME} admin for VPS creation", False)
            await ctx.send(embed=embed)
            return
        view = ManageView(user_id, vps_list)
        embed = await view.get_initial_embed()
        await ctx.send(embed=embed, view=view)

@bot.command(name='list-all')
@is_admin()
async def list_all_vps(ctx):
    total_vps = 0
    total_users = len(vps_data)
    running_vps = 0
    stopped_vps = 0
    suspended_vps = 0
    whitelisted_vps = 0
    vps_info = []
    user_summary = []
    for user_id, vps_list in vps_data.items():
        try:
            user = await bot.fetch_user(int(user_id))
            user_vps_count = len(vps_list)
            user_running = sum(1 for vps in vps_list if vps.get('status') == 'running' and not vps.get('suspended', False))
            user_stopped = sum(1 for vps in vps_list if vps.get('status') == 'stopped')
            user_suspended = sum(1 for vps in vps_list if vps.get('suspended', False))
            user_whitelisted = sum(1 for vps in vps_list if vps.get('whitelisted', False))

            total_vps += user_vps_count
            running_vps += user_running
            stopped_vps += user_stopped
            suspended_vps += user_suspended
            whitelisted_vps += user_whitelisted

            user_summary.append(f"**{user.name}** ({user.mention}) - {user_vps_count} {BRAND_NAME} VPS ({user_running} running, {user_suspended} suspended, {user_whitelisted} whitelisted)")

            for i, vps in enumerate(vps_list):
                status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
                status_text = vps.get('status', 'unknown').upper()
                if vps.get('suspended', False):
                    status_text += " (SUSPENDED)"
                if vps.get('whitelisted', False):
                    status_text += " (WHITELISTED)"
                vps_info.append(f"{status_emoji} **{user.name}** - VPS {i+1}: `{vps['container_name']}` - {vps.get('config', 'Custom')} - {status_text}")

        except discord.NotFound:
            vps_info.append(f"🔹 Unknown User ({user_id}) - {len(vps_list)} {BRAND_NAME} VPS")
    embed = create_embed(f"All {BRAND_NAME} VPS Information", f"Complete overview of all {BRAND_NAME} VPS deployments and user statistics", 0x2b2d31)
    add_field(embed, "System Overview", f"**Total Users:** {total_users}\n**Total VPS:** {total_vps}\n**Running:** {running_vps}\n**Stopped:** {stopped_vps}\n**Suspended:** {suspended_vps}\n**Whitelisted:** {whitelisted_vps}", False)
    await ctx.send(embed=embed)
    if user_summary:
        embed = create_embed(f"{BRAND_NAME} User Summary", f"Summary of all users and their {BRAND_NAME} VPS", 0x2b2d31)
        summary_text = "\n".join(user_summary)
        chunks = [summary_text[i:i+1024] for i in range(0, len(summary_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            add_field(embed, f"Users (Part {idx})", chunk, False)
        await ctx.send(embed=embed)
    if vps_info:
        vps_text = "\n".join(vps_info)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"{BRAND_NAME} VPS Details (Part {idx})", f"List of all {BRAND_NAME} VPS deployments", 0x2b2d31)
            add_field(embed, "VPS List", chunk, False)
            await ctx.send(embed=embed)

@bot.command(name='manage-shared')
async def manage_shared_vps(ctx, owner: discord.Member, vps_number: int):
    owner_id = str(owner.id)
    user_id = str(ctx.author.id)
    if owner_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[owner_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", f"Invalid VPS number or owner doesn't have a {BRAND_NAME} VPS."))
        return
    vps = vps_data[owner_id][vps_number - 1]
    if user_id not in vps.get("shared_with", []):
        await ctx.send(embed=create_error_embed("Access Denied", f"You do not have access to this {BRAND_NAME} VPS."))
        return
    view = ManageView(user_id, [vps], is_shared=True, owner_id=owner_id, actual_index=vps_number - 1)
    embed = await view.get_initial_embed()
    await ctx.send(embed=embed, view=view)

@bot.command(name='share-user')
async def share_user(ctx, shared_user: discord.Member, vps_number: int):
    user_id = str(ctx.author.id)
    shared_user_id = str(shared_user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a XeloraCloud VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    if "shared_with" not in vps:
        vps["shared_with"] = []
    if shared_user_id in vps["shared_with"]:
        await ctx.send(embed=create_error_embed("Already Shared", f"{shared_user.mention} already has access to this {BRAND_NAME} VPS!"))
        return
    vps["shared_with"].append(shared_user_id)
    save_vps_data()
    await ctx.send(embed=create_success_embed("VPS Shared", f"{BRAND_NAME} VPS #{vps_number} shared with {shared_user.mention}!"))
    try:
        await shared_user.send(embed=create_embed(f"{BRAND_NAME} VPS Access Granted", f"You have access to VPS #{vps_number} from {ctx.author.mention}. Use `!manage-shared {ctx.author.mention} {vps_number}`", 0x57f287))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {shared_user.mention}"))

@bot.command(name='share-ruser')
async def revoke_share(ctx, shared_user: discord.Member, vps_number: int):
    user_id = str(ctx.author.id)
    shared_user_id = str(shared_user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a XeloraCloud VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    if "shared_with" not in vps:
        vps["shared_with"] = []
    if shared_user_id not in vps["shared_with"]:
        await ctx.send(embed=create_error_embed("Not Shared", f"{shared_user.mention} doesn't have access to this XeloraCloud VPS!"))
        return
    vps["shared_with"].remove(shared_user_id)
    save_vps_data()
    await ctx.send(embed=create_success_embed("Access Revoked", f"Access to {BRAND_NAME} VPS #{vps_number} revoked from {shared_user.mention}!"))
    try:
        await shared_user.send(embed=create_embed("XeloraCloud VPS Access Revoked", f"Your access to VPS #{vps_number} by {ctx.author.mention} has been revoked.", 0xff3366))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {shared_user.mention}"))

@bot.command(name='delete-vps')
@is_admin()
async def delete_vps(ctx, user: discord.Member, vps_number: int, *, reason: str = "No reason"):
    user_id = str(user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or user doesn't have a XeloraCloud VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    container_name = vps["container_name"]
    await ctx.send(embed=create_info_embed(f"Deleting {BRAND_NAME} VPS", f"Removing VPS #{vps_number}..."))
    try:
        await execute_lxc(f"lxc delete {container_name} --force")
        del vps_data[user_id][vps_number - 1]
        if not vps_data[user_id]:
            del vps_data[user_id]
            if ctx.guild:
                vps_role = await get_or_create_vps_role(ctx.guild)
                if vps_role and vps_role in user.roles:
                    try:
                        await user.remove_roles(vps_role, reason="No XeloraCloud VPS ownership")
                    except discord.Forbidden:
                        logger.warning(f"Failed to remove XeloraCloud VPS role from {user.name}")
        save_vps_data()
        embed = create_success_embed("XeloraCloud VPS Deleted Successfully")
        add_field(embed, "Owner", user.mention, True)
        add_field(embed, "VPS ID", f"#{vps_number}", True)
        add_field(embed, "Container", f"`{container_name}`", True)
        add_field(embed, "Reason", reason, False)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Deletion Failed", f"Error: {str(e)}"))

@bot.command(name='add-resources')
@is_admin()
async def add_resources(ctx, vps_id: str, ram: int = None, cpu: int = None, disk: int = None):
    if ram is None and cpu is None and disk is None:
        await ctx.send(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to add (ram, cpu, or disk)"))
        return
    found_vps = None
    user_id = None
    vps_index = None
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == vps_id:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    if not found_vps:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No XeloraCloud VPS found with ID: `{vps_id}`"))
        return
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    disk_changed = disk is not None
    if was_running:
        await ctx.send(embed=create_info_embed("Stopping VPS", f"Stopping XeloraCloud VPS `{vps_id}` to apply resource changes..."))
        try:
            await execute_lxc(f"lxc stop {vps_id}")
            found_vps['status'] = 'stopped'
            save_vps_data()
        except Exception as e:
            await ctx.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"))
            return
    changes = []
    try:
        current_ram_gb = int(found_vps['ram'].replace('GB', ''))
        current_cpu = int(found_vps['cpu'])
        current_disk_gb = int(found_vps['storage'].replace('GB', ''))

        new_ram_gb = current_ram_gb
        new_cpu = current_cpu
        new_disk_gb = current_disk_gb

        if ram is not None and ram > 0:
            new_ram_gb += ram
            ram_mb = new_ram_gb * 1024
            await execute_lxc(f"lxc config set {vps_id} limits.memory {ram_mb}MB")
            changes.append(f"RAM: +{ram}GB (New total: {new_ram_gb}GB)")

        if cpu is not None and cpu > 0:
            new_cpu += cpu
            await execute_lxc(f"lxc config set {vps_id} limits.cpu {new_cpu}")
            changes.append(f"CPU: +{cpu} cores (New total: {new_cpu} cores)")

        if disk is not None and disk > 0:
            new_disk_gb += disk
            await execute_lxc(f"lxc config device set {vps_id} root size={new_disk_gb}GB")
            changes.append(f"Disk: +{disk}GB (New total: {new_disk_gb}GB)")

        found_vps['ram'] = f"{new_ram_gb}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk_gb}GB"
        found_vps['config'] = f"{new_ram_gb}GB RAM / {new_cpu} CPU / {new_disk_gb}GB Disk"

        vps_data[user_id][vps_index] = found_vps
        save_vps_data()

        if was_running:
            await execute_lxc(f"lxc start {vps_id}")
            found_vps['status'] = 'running'
            save_vps_data()

        embed = create_success_embed("Resources Added", f"Successfully added resources to XeloraCloud VPS `{vps_id}`")
        add_field(embed, "Changes Applied", "\n".join(changes), False)
        if disk_changed:
            add_field(embed, "Disk Note", "Run `sudo resize2fs /` inside the VPS to expand the filesystem.", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Resource Addition Failed", f"Error: {str(e)}"))

@bot.command(name='admin-add')
@is_main_admin()
async def admin_add(ctx, user: discord.Member):
    user_id = str(user.id)
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Already Admin", "This user is already the main XeloraCloud admin!"))
        return
    if user_id in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Already Admin", f"{user.mention} is already a XeloraCloud admin!"))
        return
    admin_data["admins"].append(user_id)
    save_admin_data()
    await ctx.send(embed=create_success_embed("Admin Added", f"{user.mention} is now a XeloraCloud admin!"))
    try:
        await user.send(embed=create_embed("🎉 XeloraCloud Admin Role Granted", f"You are now a XeloraCloud admin by {ctx.author.mention}", 0x00ff88))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"))

@bot.command(name='admin-remove')
@is_main_admin()
async def admin_remove(ctx, user: discord.Member):
    user_id = str(user.id)
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Cannot Remove", "You cannot remove the main XeloraCloud admin!"))
        return
    if user_id not in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Not Admin", f"{user.mention} is not a XeloraCloud admin!"))
        return
    admin_data["admins"].remove(user_id)
    save_admin_data()
    await ctx.send(embed=create_success_embed("Admin Removed", f"{user.mention} is no longer a XeloraCloud admin!"))
    try:
        await user.send(embed=create_embed("⚠️ XeloraCloud Admin Role Revoked", f"Your admin role was removed by {ctx.author.mention}", 0xff3366))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"))

@bot.command(name='admin-list')
@is_main_admin()
async def admin_list(ctx):
    admins = admin_data.get("admins", [])
    main_admin = await bot.fetch_user(MAIN_ADMIN_ID)
    embed = create_embed("👑 XeloraCloud Admin Team", "Current XeloraCloud administrators:", 0x1a1a1a)
    add_field(embed, "🔰 Main Admin", f"{main_admin.mention} (ID: {MAIN_ADMIN_ID})", False)
    if admins:
        admin_list = []
        for admin_id in admins:
            try:
                admin_user = await bot.fetch_user(int(admin_id))
                admin_list.append(f"• {admin_user.mention} (ID: {admin_id})")
            except:
                admin_list.append(f"• Unknown User (ID: {admin_id})")
        admin_text = "\n".join(admin_list)
        add_field(embed, "🛡️ Admins", admin_text, False)
    else:
        add_field(embed, "🛡️ Admins", "No additional XeloraCloud admins", False)
    await ctx.send(embed=embed)

@bot.command(name='userinfo')
@is_admin()
async def user_info(ctx, user: discord.Member):
    user_id = str(user.id)
    vps_list = vps_data.get(user_id, [])
    embed = create_embed(f"XeloraCloud User Information - {user.name}", f"Detailed information for {user.mention}", 0x1a1a1a)
    add_field(embed, "👤 User Details", f"**Name:** {user.name}\n**ID:** {user.id}\n**Joined:** {user.joined_at.strftime('%Y-%m-%d %H:%M:%S') if user.joined_at else 'Unknown'}", False)
    if vps_list:
        vps_info = []
        total_ram = 0
        total_cpu = 0
        total_storage = 0
        running_count = 0
        suspended_count = 0
        whitelisted_count = 0
        for i, vps in enumerate(vps_list):
            status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
            status_text = vps.get('status', 'unknown').upper()
            if vps.get('suspended', False):
                status_text += " (SUSPENDED)"
                suspended_count += 1
            else:
                running_count += 1 if vps.get('status') == 'running' else 0
            if vps.get('whitelisted', False):
                whitelisted_count += 1
            vps_info.append(f"{status_emoji} VPS {i+1}: `{vps['container_name']}` - {status_text}")
            ram_gb = int(vps['ram'].replace('GB', ''))
            storage_gb = int(vps['storage'].replace('GB', ''))
            total_ram += ram_gb
            total_cpu += int(vps['cpu'])
            total_storage += storage_gb
        vps_summary = f"**Total VPS:** {len(vps_list)}\n**Running:** {running_count}\n**Suspended:** {suspended_count}\n**Whitelisted:** {whitelisted_count}\n**Total RAM:** {total_ram}GB\n**Total CPU:** {total_cpu} cores\n**Total Storage:** {total_storage}GB"
        add_field(embed, "🖥️ XeloraCloud VPS Information", vps_summary, False)

        vps_text = "\n".join(vps_info)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            add_field(embed, f"📋 VPS List (Part {idx})", chunk, False)
    else:
        add_field(embed, "🖥️ XeloraCloud VPS Information", "**No VPS owned**", False)
    is_admin_user = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
    add_field(embed, "🛡️ XeloraCloud Admin Status", f"**{'Yes' if is_admin_user else 'No'}**", False)
    await ctx.send(embed=embed)

@bot.command(name='serverstats')
@is_admin()
async def server_stats(ctx):
    total_users = len(vps_data)
    total_vps = sum(len(vps_list) for vps_list in vps_data.values())
    total_ram = 0
    total_cpu = 0
    total_storage = 0
    running_vps = 0
    suspended_vps = 0
    whitelisted_vps = 0
    for vps_list in vps_data.values():
        for vps in vps_list:
            ram_gb = int(vps['ram'].replace('GB', ''))
            storage_gb = int(vps['storage'].replace('GB', ''))
            total_ram += ram_gb
            total_cpu += int(vps['cpu'])
            total_storage += storage_gb
            if vps.get('status') == 'running':
                if vps.get('suspended', False):
                    suspended_vps += 1
                else:
                    running_vps += 1
            if vps.get('whitelisted', False):
                whitelisted_vps += 1
    embed = create_embed("📊 XeloraCloud Server Statistics", "Current XeloraCloud server overview", 0x1a1a1a)
    add_field(embed, "👥 Users", f"**Total Users:** {total_users}\n**Total Admins:** {len(admin_data.get('admins', [])) + 1}", False)
    add_field(embed, "🖥️ VPS", f"**Total VPS:** {total_vps}\n**Running:** {running_vps}\n**Suspended:** {suspended_vps}\n**Whitelisted:** {whitelisted_vps}\n**Stopped:** {total_vps - running_vps - suspended_vps}", False)
    add_field(embed, "📈 Resources", f"**Total RAM:** {total_ram}GB\n**Total CPU:** {total_cpu} cores\n**Total Storage:** {total_storage}GB", False)
    await ctx.send(embed=embed)

@bot.command(name='vpsinfo')
@is_admin()
async def vps_info(ctx, container_name: str = None):
    if not container_name:
        all_vps = []
        for user_id, vps_list in vps_data.items():
            try:
                user = await bot.fetch_user(int(user_id))
                for i, vps in enumerate(vps_list):
                    status_text = vps.get('status', 'unknown').upper()
                    if vps.get('suspended', False):
                        status_text += " (SUSPENDED)"
                    if vps.get('whitelisted', False):
                        status_text += " (WHITELISTED)"
                    all_vps.append(f"**{user.name}** - XeloraCloud VPS {i+1}: `{vps['container_name']}` - {status_text}")
            except:
                pass
        vps_text = "\n".join(all_vps)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"🖥️ All XeloraCloud VPS (Part {idx})", f"List of all XeloraCloud VPS deployments", 0x1a1a1a)
            add_field(embed, "VPS List", chunk, False)
            await ctx.send(embed=embed)
    else:
        found_vps = None
        found_user = None
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    found_user = await bot.fetch_user(int(user_id))
                    break
            if found_vps:
                break
        if not found_vps:
            await ctx.send(embed=create_error_embed("VPS Not Found", f"No XeloraCloud VPS found with container name: `{container_name}`"))
            return
        suspended_text = " (SUSPENDED)" if found_vps.get('suspended', False) else ""
        whitelisted_text = " (WHITELISTED)" if found_vps.get('whitelisted', False) else ""
        embed = create_embed(f"🖥️ XeloraCloud VPS Information - {container_name}", f"Details for VPS owned by {found_user.mention}{suspended_text}{whitelisted_text}", 0x1a1a1a)
        add_field(embed, "👤 Owner", f"**Name:** {found_user.name}\n**ID:** {found_user.id}", False)
        add_field(embed, "📊 Specifications", f"**RAM:** {found_vps['ram']}\n**CPU:** {found_vps['cpu']} Cores\n**Storage:** {found_vps['storage']}", False)
        add_field(embed, "📈 Status", f"**Current:** {found_vps.get('status', 'unknown').upper()}{suspended_text}{whitelisted_text}\n**Suspended:** {found_vps.get('suspended', False)}\n**Whitelisted:** {found_vps.get('whitelisted', False)}\n**Created:** {found_vps.get('created_at', 'Unknown')}", False)
        if 'config' in found_vps:
            add_field(embed, "⚙️ Configuration", f"**Config:** {found_vps['config']}", False)
        if found_vps.get('shared_with'):
            shared_users = []
            for shared_id in found_vps['shared_with']:
                try:
                    shared_user = await bot.fetch_user(int(shared_id))
                    shared_users.append(f"• {shared_user.mention}")
                except:
                    shared_users.append(f"• Unknown User ({shared_id})")
            shared_text = "\n".join(shared_users)
            add_field(embed, "🔗 Shared With", shared_text, False)
        await ctx.send(embed=embed)

@bot.command(name='restart-vps')
@is_admin()
async def restart_vps(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Restarting VPS", f"Restarting XeloraCloud VPS `{container_name}`..."))
    try:
        await execute_lxc(f"lxc restart {container_name}")
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break
        await ctx.send(embed=create_success_embed("VPS Restarted", f"XeloraCloud VPS `{container_name}` has been restarted successfully!"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Restart Failed", f"Error: {str(e)}"))

@bot.command(name='exec')
@is_admin()
async def execute_command(ctx, container_name: str, *, command: str):
    await ctx.send(embed=create_info_embed("Executing Command", f"Running command in XeloraCloud VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "bash", "-c", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode() if stdout else "No output"
        error = stderr.decode() if stderr else ""
        embed = create_embed(f"Command Output - {container_name}", f"Command: `{command}`", 0x1a1a1a)
        if output.strip():
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"
            add_field(embed, "📤 Output", f"```\n{output}\n```", False)
        if error.strip():
            if len(error) > 1000:
                error = error[:1000] + "\n... (truncated)"
            add_field(embed, "⚠️ Error", f"```\n{error}\n```", False)
        add_field(embed, "🔄 Exit Code", f"**{proc.returncode}**", False)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Execution Failed", f"Error: {str(e)}"))

@bot.command(name='stop-vps-all')
@is_admin()
async def stop_all_vps(ctx):
    embed = create_warning_embed("Stopping All XeloraCloud VPS", "⚠️ **WARNING:** This will stop ALL running VPS on the XeloraCloud server.\n\nThis action cannot be undone. Continue?")
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)

        @discord.ui.button(label="Stop All VPS", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.defer()
            try:
                proc = await asyncio.create_subprocess_exec(
                    "lxc", "stop", "--all", "--force",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode == 0:
                    stopped_count = 0
                    for user_id, vps_list in vps_data.items():
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                vps['status'] = 'stopped'
                                vps['suspended'] = False
                                stopped_count += 1
                    save_vps_data()
                    embed = create_success_embed("All XeloraCloud VPS Stopped", f"Successfully stopped {stopped_count} VPS using `lxc stop --all --force`")
                    output_text = stdout.decode() if stdout else 'No output'
                    add_field(embed, "Command Output", f"```\n{output_text}\n```", False)
                    await interaction.followup.send(embed=embed)
                else:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    embed = create_error_embed("Stop Failed", f"Failed to stop XeloraCloud VPS: {error_msg}")
                    await interaction.followup.send(embed=embed)
            except Exception as e:
                embed = create_error_embed("Error", f"Error stopping VPS: {str(e)}")
                await interaction.followup.send(embed=embed)

        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.edit_message(embed=create_info_embed("Operation Cancelled", "The stop all XeloraCloud VPS operation has been cancelled."))
    await ctx.send(embed=embed, view=ConfirmView())

@bot.command(name='cpu-monitor')
@is_admin()
async def resource_monitor_control(ctx, action: str = "status"):
    global resource_monitor_active
    if action.lower() == "status":
        status = "Active" if resource_monitor_active else "Inactive"
        embed = create_embed("XeloraCloud Resource Monitor Status", f"XeloraCloud resource monitoring is currently **{status}**", 0x00ccff if resource_monitor_active else 0xffaa00)
        add_field(embed, "Thresholds", f"{CPU_THRESHOLD}% CPU / {RAM_THRESHOLD}% RAM usage", True)
        add_field(embed, "Check Interval", f"60 seconds (host)", True)
        await ctx.send(embed=embed)
    elif action.lower() == "enable":
        resource_monitor_active = True
        await ctx.send(embed=create_success_embed("Resource Monitor Enabled", "XeloraCloud resource monitoring has been enabled."))
    elif action.lower() == "disable":
        resource_monitor_active = False
        await ctx.send(embed=create_warning_embed("Resource Monitor Disabled", "XeloraCloud resource monitoring has been disabled."))
    else:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use: `!cpu-monitor <status|enable|disable>`"))

@bot.command(name='resize-vps')
@is_admin()
async def resize_vps(ctx, container_name: str, ram: int = None, cpu: int = None, disk: int = None):
    if ram is None and cpu is None and disk is None:
        await ctx.send(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to resize (ram, cpu, or disk)"))
        return
    found_vps = None
    user_id = None
    vps_index = None
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == container_name:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    if not found_vps:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No XeloraCloud VPS found with container name: `{container_name}`"))
        return
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    disk_changed = disk is not None
    if was_running:
        await ctx.send(embed=create_info_embed("Stopping VPS", f"Stopping XeloraCloud VPS `{container_name}` to apply resource changes..."))
        try:
            await execute_lxc(f"lxc stop {container_name}")
            found_vps['status'] = 'stopped'
            save_vps_data()
        except Exception as e:
            await ctx.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"))
            return
    changes = []
    try:
        new_ram = int(found_vps['ram'].replace('GB', ''))
        new_cpu = int(found_vps['cpu'])
        new_disk = int(found_vps['storage'].replace('GB', ''))

        if ram is not None and ram > 0:
            new_ram = ram
            ram_mb = ram * 1024
            await execute_lxc(f"lxc config set {container_name} limits.memory {ram_mb}MB")
            changes.append(f"RAM: {ram}GB")

        if cpu is not None and cpu > 0:
            new_cpu = cpu
            await execute_lxc(f"lxc config set {container_name} limits.cpu {cpu}")
            changes.append(f"CPU: {cpu} cores")

        if disk is not None and disk > 0:
            new_disk = disk
            await execute_lxc(f"lxc config device set {container_name} root size={disk}GB")
            changes.append(f"Disk: {disk}GB")

        found_vps['ram'] = f"{new_ram}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk}GB"
        found_vps['config'] = f"{new_ram}GB RAM / {new_cpu} CPU / {new_disk}GB Disk"

        vps_data[user_id][vps_index] = found_vps
        save_vps_data()

        if was_running:
            await execute_lxc(f"lxc start {container_name}")
            found_vps['status'] = 'running'
            save_vps_data()

        embed = create_success_embed("VPS Resized", f"Successfully resized resources for XeloraCloud VPS `{container_name}`")
        add_field(embed, "Changes Applied", "\n".join(changes), False)
        if disk_changed:
            add_field(embed, "Disk Note", "Run `sudo resize2fs /` inside the VPS to expand the filesystem.", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Resize Failed", f"Error: {str(e)}"))

@bot.command(name='clone-vps')
@is_admin()
async def clone_vps(ctx, container_name: str, new_name: str = None):
    if not new_name:
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        new_name = f"XeloraCloud-{container_name}-clone-{timestamp}"
    await ctx.send(embed=create_info_embed("Cloning VPS", f"Cloning XeloraCloud VPS `{container_name}` to `{new_name}`..."))
    try:
        found_vps = None
        user_id = None

        for uid, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    user_id = uid
                    break
            if found_vps:
                break

        if not found_vps:
            await ctx.send(embed=create_error_embed("VPS Not Found", f"No XeloraCloud VPS found with container name: `{container_name}`"))
            return

        await execute_lxc(f"lxc copy {container_name} {new_name}")
        await apply_advanced_permissions(new_name)
        await execute_lxc(f"lxc start {new_name}")

        if user_id not in vps_data:
            vps_data[user_id] = []

        new_vps = found_vps.copy()
        new_vps['container_name'] = new_name
        new_vps['status'] = 'running'
        new_vps['suspended'] = False
        new_vps['whitelisted'] = False
        new_vps['suspension_history'] = []
        new_vps['created_at'] = datetime.now().isoformat()
        new_vps['shared_with'] = []
        new_vps['id'] = None

        vps_data[user_id].append(new_vps)
        save_vps_data()

        embed = create_success_embed("VPS Cloned", f"Successfully cloned XeloraCloud VPS `{container_name}` to `{new_name}`")
        add_field(embed, "New VPS Details", f"**RAM:** {new_vps['ram']}\n**CPU:** {new_vps['cpu']} Cores\n**Storage:** {new_vps['storage']}", False)
        add_field(embed, "Features", "Nesting, Privileged, FUSE, Kernel Modules (Docker Ready)", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Clone Failed", f"Error: {str(e)}"))

@bot.command(name='migrate-vps')
@is_admin()
async def migrate_vps(ctx, container_name: str, target_pool: str):
    await ctx.send(embed=create_info_embed("Migrating VPS", f"Migrating {BRAND_NAME} VPS `{container_name}` to storage pool `{target_pool}`..."))
    try:
        await execute_lxc(f"lxc stop {container_name}")

        temp_name = f"XeloraCloud-{container_name}-temp-{int(time.time())}"

        await execute_lxc(f"lxc copy {container_name} {temp_name} -s {target_pool}")

        await execute_lxc(f"lxc delete {container_name} --force")

        await execute_lxc(f"lxc rename {temp_name} {container_name}")

        await apply_advanced_permissions(container_name)

        await execute_lxc(f"lxc start {container_name}")

        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break

        await ctx.send(embed=create_success_embed("VPS Migrated", f"Successfully migrated {BRAND_NAME} VPS `{container_name}` to storage pool `{target_pool}`"))

    except Exception as e:
        await ctx.send(embed=create_error_embed("Migration Failed", f"Error: {str(e)}"))

@bot.command(name='vps-stats')
@is_admin()
async def vps_stats(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Gathering Statistics", f"Collecting statistics for XeloraCloud VPS `{container_name}`..."))
    try:
        status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        uptime = await get_container_uptime(container_name)
        proc = await asyncio.create_subprocess_exec(
            "lxc", "info", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        network_usage = "N/A"
        for line in output.splitlines():
            if "Network usage" in line:
                network_usage = line.split(":")[1].strip()
                break

        embed = create_embed(f"📊 XeloraCloud VPS Statistics - {container_name}", f"Resource usage statistics", 0x1a1a1a)
        add_field(embed, "📈 Status", f"**{status.upper()}**", False)
        add_field(embed, "💻 CPU Usage", f"**{cpu_usage}**", True)
        add_field(embed, "🧠 Memory Usage", f"**{memory_usage}**", True)
        add_field(embed, "💾 Disk Usage", f"**{disk_usage}**", True)
        add_field(embed, "⏱️ Uptime", f"**{uptime}**", True)
        add_field(embed, "🌐 Network Usage", f"**{network_usage}**", False)

        found_vps = None
        for vps_list in vps_data.values():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    break
            if found_vps:
                break

        if found_vps:
            suspended_text = " (SUSPENDED)" if found_vps.get('suspended', False) else ""
            whitelisted_text = " (WHITELISTED)" if found_vps.get('whitelisted', False) else ""
            add_field(embed, "📋 Allocated Resources",
                           f"**RAM:** {found_vps['ram']}\n**CPU:** {found_vps['cpu']} Cores\n**Storage:** {found_vps['storage']}\n**Status:** {found_vps.get('status', 'unknown').upper()}{suspended_text}{whitelisted_text}",
                           False)

        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Statistics Failed", f"Error: {str(e)}"))

@bot.command(name='vps-network')
@is_admin()
async def vps_network(ctx, container_name: str, action: str, value: str = None):
    if action.lower() not in ["list", "add", "remove", "limit"]:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use: `!vps-network <container> <list|add|remove|limit> [value]`"))
        return
    try:
        if action.lower() == "list":
            proc = await asyncio.create_subprocess_exec(
                "lxc", "exec", container_name, "--", "ip", "addr",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()
                if len(output) > 1000:
                    output = output[:1000] + "\n... (truncated)"

                embed = create_embed(f"🌐 XeloraCloud Network Interfaces - {container_name}", "Network configuration", 0x1a1a1a)
                add_field(embed, "Interfaces", f"```\n{output}\n```", False)
                await ctx.send(embed=embed)
            else:
                await ctx.send(embed=create_error_embed("Error", f"Failed to list network interfaces: {stderr.decode()}"))

        elif action.lower() == "limit" and value:
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.egress {value}")
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.ingress {value}")
            await ctx.send(embed=create_success_embed("Network Limited", f"Set XeloraCloud network limit to {value} for `{container_name}`"))

        elif action.lower() == "add" and value:
            await execute_lxc(f"lxc config device add {container_name} eth1 nic nictype=bridged parent={value}")
            await ctx.send(embed=create_success_embed("Network Added", f"Added network interface to XeloraCloud VPS `{container_name}` with bridge `{value}`"))

        elif action.lower() == "remove" and value:
            await execute_lxc(f"lxc config device remove {container_name} {value}")
            await ctx.send(embed=create_success_embed("Network Removed", f"Removed network interface `{value}` from XeloraCloud VPS `{container_name}`"))

        else:
            await ctx.send(embed=create_error_embed("Invalid Parameters", "Please provide valid parameters for the action"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Network Management Failed", f"Error: {str(e)}"))

@bot.command(name='vps-processes')
@is_admin()
async def vps_processes(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Gathering Processes", f"Listing processes in XeloraCloud VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "ps", "aux",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            output = stdout.decode()
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"

            embed = create_embed(f"⚙️ XeloraCloud Processes - {container_name}", "Running processes", 0x1a1a1a)
            add_field(embed, "Process List", f"```\n{output}\n```", False)
            await ctx.send(embed=embed)
        else:
            await ctx.send(embed=create_error_embed("Error", f"Failed to list processes: {stderr.decode()}"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Process Listing Failed", f"Error: {str(e)}"))

@bot.command(name='vps-logs')
@is_admin()
async def vps_logs(ctx, container_name: str, lines: int = 50):
    await ctx.send(embed=create_info_embed("Gathering Logs", f"Fetching last {lines} lines from XeloraCloud VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "journalctl", "-n", str(lines),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            output = stdout.decode()
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"

            embed = create_embed(f"📋 XeloraCloud Logs - {container_name}", f"Last {lines} log lines", 0x1a1a1a)
            add_field(embed, "System Logs", f"```\n{output}\n```", False)
            await ctx.send(embed=embed)
        else:
            await ctx.send(embed=create_error_embed("Error", f"Failed to fetch logs: {stderr.decode()}"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Log Retrieval Failed", f"Error: {str(e)}"))

@bot.command(name='vps-uptime')
@is_admin()
async def vps_uptime(ctx, container_name: str):
    uptime = await get_container_uptime(container_name)
    embed = create_info_embed("VPS Uptime", f"Uptime for `{container_name}`: {uptime}")
    await ctx.send(embed=embed)

@bot.command(name='suspend-vps')
@is_admin()
async def suspend_vps(ctx, container_name: str, *, reason: str = "Admin action"):
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if vps.get('status') != 'running':
                    await ctx.send(embed=create_error_embed("Cannot Suspend", "XeloraCloud VPS must be running to suspend."))
                    return
                try:
                    await execute_lxc(f"lxc stop {container_name}")
                    vps['status'] = 'stopped'
                    vps['suspended'] = True
                    if 'suspension_history' not in vps:
                        vps['suspension_history'] = []
                    vps['suspension_history'].append({
                        'time': datetime.now().isoformat(),
                        'reason': reason,
                        'by': f"{ctx.author.name} ({ctx.author.id})"
                    })
                    save_vps_data()
                except Exception as e:
                    await ctx.send(embed=create_error_embed("Suspend Failed", str(e)))
                    return
                try:
                    owner = await bot.fetch_user(int(uid))
                    embed = create_warning_embed("🚨 XeloraCloud VPS Suspended", f"Your VPS `{container_name}` has been suspended by an admin.\n\n**Reason:** {reason}\n\nContact a XeloraCloud admin to unsuspend.")
                    await owner.send(embed=embed)
                except Exception as dm_e:
                    logger.error(f"Failed to DM owner {uid}: {dm_e}")
                await ctx.send(embed=create_success_embed("VPS Suspended", f"XeloraCloud VPS `{container_name}` suspended. Reason: {reason}"))
                found = True
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"XeloraCloud VPS `{container_name}` not found."))

@bot.command(name='unsuspend-vps')
@is_admin()
async def unsuspend_vps(ctx, container_name: str):
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if not vps.get('suspended', False):
                    await ctx.send(embed=create_error_embed("Not Suspended", "XeloraCloud VPS is not suspended."))
                    return
                try:
                    vps['suspended'] = False
                    vps['status'] = 'running'
                    await execute_lxc(f"lxc start {container_name}")
                    save_vps_data()
                    await ctx.send(embed=create_success_embed("VPS Unsuspended", f"XeloraCloud VPS `{container_name}` unsuspended and started."))
                    found = True
                except Exception as e:
                    await ctx.send(embed=create_error_embed("Start Failed", str(e)))
                try:
                    owner = await bot.fetch_user(int(uid))
                    embed = create_success_embed("🟢 XeloraCloud VPS Unsuspended", f"Your VPS `{container_name}` has been unsuspended by an admin.\nYou can now manage it again.")
                    await owner.send(embed=embed)
                except Exception as dm_e:
                    logger.error(f"Failed to DM owner {uid} about unsuspension: {dm_e}")
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"XeloraCloud VPS `{container_name}` not found."))

@bot.command(name='suspension-logs')
@is_admin()
async def suspension_logs(ctx, container_name: str = None):
    if container_name:
        found = None
        for lst in vps_data.values():
            for vps in lst:
                if vps['container_name'] == container_name:
                    found = vps
                    break
            if found:
                break
        if not found:
            await ctx.send(embed=create_error_embed("Not Found", f"XeloraCloud VPS `{container_name}` not found."))
            return
        history = found.get('suspension_history', [])
        if not history:
            await ctx.send(embed=create_info_embed("No Suspensions", f"No XeloraCloud suspension history for `{container_name}`."))
            return
        embed = create_embed("XeloraCloud Suspension History", f"For `{container_name}`")
        text = []
        for h in sorted(history, key=lambda x: x['time'], reverse=True)[:10]:
            t = datetime.fromisoformat(h['time']).strftime('%Y-%m-%d %H:%M:%S')
            text.append(f"**{t}** - {h['reason']} (by {h['by']})")
        add_field(embed, "History", "\n".join(text), False)
        if len(history) > 10:
            add_field(embed, "Note", "Showing last 10 entries.")
        await ctx.send(embed=embed)
    else:
        all_logs = []
        for uid, lst in vps_data.items():
            for vps in lst:
                h = vps.get('suspension_history', [])
                for event in sorted(h, key=lambda x: x['time'], reverse=True):
                    t = datetime.fromisoformat(event['time']).strftime('%Y-%m-%d %H:%M')
                    all_logs.append(f"**{t}** - VPS `{vps['container_name']}` (Owner: <@{uid}>) - {event['reason']} (by {event['by']})")
        if not all_logs:
            await ctx.send(embed=create_info_embed("No Suspensions", "No XeloraCloud suspension events recorded."))
            return
        logs_text = "\n".join(all_logs)
        chunks = [logs_text[i:i+1024] for i in range(0, len(logs_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"XeloraCloud Suspension Logs (Part {idx})", f"Global suspension events (newest first)")
            add_field(embed, "Events", chunk, False)
            await ctx.send(embed=embed)

@bot.command(name='apply-permissions')
@is_admin()
async def apply_permissions(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Applying Permissions", f"Applying advanced permissions to `{container_name}`..."))
    try:
        status = await get_container_status(container_name)
        was_running = status == 'running'
        if was_running:
            await execute_lxc(f"lxc stop {container_name}")

        await apply_advanced_permissions(container_name)

        await execute_lxc(f"lxc start {container_name}")

        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break

        await ctx.send(embed=create_success_embed("Permissions Applied", f"Advanced permissions applied to XeloraCloud VPS `{container_name}`. Docker-ready!"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Apply Failed", f"Error: {str(e)}"))

@bot.command(name='resource-check')
@is_admin()
async def resource_check(ctx):
    suspended_count = 0
    embed = create_info_embed("Resource Check", "Checking all running VPS for high resource usage...")
    msg = await ctx.send(embed=embed)
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            if vps.get('status') == 'running' and not vps.get('suspended', False) and not vps.get('whitelisted', False):
                container = vps['container_name']
                cpu = await get_container_cpu_pct(container)
                ram = await get_container_ram_pct(container)
                if cpu > CPU_THRESHOLD or ram > RAM_THRESHOLD:
                    reason = f"High resource usage: CPU {cpu:.1f}%, RAM {ram:.1f}% (threshold: {CPU_THRESHOLD}% CPU / {RAM_THRESHOLD}% RAM)"
                    logger.warning(f"Suspending {container}: {reason}")
                    try:
                        await execute_lxc(f"lxc stop {container}")
                        vps['status'] = 'stopped'
                        vps['suspended'] = True
                        if 'suspension_history' not in vps:
                            vps['suspension_history'] = []
                        vps['suspension_history'].append({
                            'time': datetime.now().isoformat(),
                            'reason': reason,
                            'by': 'XeloraCloud Auto Resource Check'
                        })
                        save_vps_data()
                        try:
                            owner = await bot.fetch_user(int(user_id))
                            warn_embed = create_warning_embed("🚨 VPS Auto-Suspended", f"Your VPS `{container}` has been automatically suspended due to high resource usage.\n\n**Reason:** {reason}\n\nContact XeloraCloud admin to unsuspend and address the issue.")
                            await owner.send(embed=warn_embed)
                        except Exception as dm_e:
                            logger.error(f"Failed to DM owner {user_id}: {dm_e}")
                        suspended_count += 1
                    except Exception as e:
                        logger.error(f"Failed to suspend {container}: {e}")
    final_embed = create_info_embed("Resource Check Complete", f"Checked all VPS. Suspended {suspended_count} high-usage VPS.")
    await msg.edit(embed=final_embed)

@bot.command(name='whitelist-vps')
@is_admin()
async def whitelist_vps(ctx, container_name: str, action: str):
    if action.lower() not in ['add', 'remove']:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use: `!whitelist-vps <container> <add|remove>`"))
        return
    found = False
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            if vps['container_name'] == container_name:
                if action.lower() == 'add':
                    vps['whitelisted'] = True
                    msg = "added to whitelist (exempt from auto-suspension)"
                else:
                    vps['whitelisted'] = False
                    msg = "removed from whitelist"
                save_vps_data()
                await ctx.send(embed=create_success_embed("Whitelist Updated", f"VPS `{container_name}` {msg}."))
                found = True
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"XeloraCloud VPS `{container_name}` not found."))

@bot.command(name='snapshot')
@is_admin()
async def snapshot_vps(ctx, container_name: str, snap_name: str = "snap0"):
    await ctx.send(embed=create_info_embed("Creating Snapshot", f"Creating snapshot '{snap_name}' for `{container_name}`..."))
    try:
        await execute_lxc(f"lxc snapshot {container_name} {snap_name}")
        await ctx.send(embed=create_success_embed("Snapshot Created", f"Snapshot '{snap_name}' created for XeloraCloud VPS `{container_name}`."))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Snapshot Failed", f"Error: {str(e)}"))

@bot.command(name='list-snapshots')
@is_admin()
async def list_snapshots(ctx, container_name: str):
    try:
        result = await execute_lxc(f"lxc snapshot list {container_name}")
        embed = create_info_embed(f"Snapshots for {container_name}", result)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("List Failed", f"Error: {str(e)}"))

@bot.command(name='restore-snapshot')
@is_admin()
async def restore_snapshot(ctx, container_name: str, snap_name: str):
    await ctx.send(embed=create_warning_embed("Restore Snapshot", f"Restoring snapshot '{snap_name}' for `{container_name}` will overwrite current state. Continue?"))
    class RestoreConfirm(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)

        @discord.ui.button(label="Confirm Restore", style=discord.ButtonStyle.danger)
        async def confirm(self, inter: discord.Interaction, item: discord.ui.Button):
            await inter.response.defer()
            try:
                await execute_lxc(f"lxc stop {container_name}")
                await execute_lxc(f"lxc restore {container_name} {snap_name}")
                await execute_lxc(f"lxc start {container_name}")
                for uid, lst in vps_data.items():
                    for vps in lst:
                        if vps['container_name'] == container_name:
                            vps['status'] = 'running'
                            vps['suspended'] = False
                            save_vps_data()
                            break
                await inter.followup.send(embed=create_success_embed("Snapshot Restored", f"Restored '{snap_name}' for XeloraCloud VPS `{container_name}`."))
            except Exception as e:
                await inter.followup.send(embed=create_error_embed("Restore Failed", f"Error: {str(e)}"))

        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, inter: discord.Interaction, item: discord.ui.Button):
            await inter.response.edit_message(embed=create_info_embed("Cancelled", "Snapshot restore cancelled."))
    await ctx.send(view=RestoreConfirm())

@bot.command(name='help')
async def show_help(ctx):
    user_id = str(ctx.author.id)
    is_user_admin = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
    is_user_main_admin = user_id == str(MAIN_ADMIN_ID)
    embed = create_embed(f"🆘 {BRAND_NAME} Command Help - User Commands", f"{BRAND_NAME} VPS Manager Commands:", 0x2b2d31)
    user_commands = [
        ("!ping", f"Check {BRAND_NAME} bot latency"),
        ("!uptime", "Show host uptime"),
        ("!myvps", f"List your {BRAND_NAME} VPS"),
        ("!manage [@user]", "Manage your VPS or another user's VPS (Admin only)"),
        ("!share-user @user <vps_number>", f"Share {BRAND_NAME} VPS access"),
        ("!share-ruser @user <vps_number>", f"Revoke {BRAND_NAME} VPS access"),
        ("!manage-shared @owner <vps_number>", f"Manage shared {BRAND_NAME} VPS")
    ]
    user_commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in user_commands])
    add_field(embed, "👤 User Commands", user_commands_text, False)
    await ctx.send(embed=embed)
    if is_user_admin:
        embed = create_embed(f"🆘 {BRAND_NAME} Command Help - Admin Commands", f"{BRAND_NAME} VPS Manager Commands:", 0x2b2d31)
        admin_commands = [
            ("!lxc-list", "List all LXC containers"),
            ("!create <ram_gb> <cpu_cores> <disk_gb> @user", "Create VPS with OS selection"),
            ("!delete-vps @user <vps_number> [reason]", f"Delete user's {BRAND_NAME} VPS"),
            ("!add-resources <container> [ram] [cpu] [disk]", f"Add resources to {BRAND_NAME} VPS"),
            ("!resize-vps <container> [ram] [cpu] [disk]", f"Resize {BRAND_NAME} VPS resources"),
            ("!suspend-vps <container> [reason]", f"Suspend {BRAND_NAME} VPS"),
            ("!unsuspend-vps <container>", f"Unsuspend {BRAND_NAME} VPS"),
            ("!suspension-logs [container]", "View suspension logs"),
            ("!whitelist-vps <container> <add|remove>", "Whitelist VPS from auto-suspend"),
            ("!resource-check", "Check and suspend high-usage VPS"),
            ("!userinfo @user", "User information"),
            ("!serverstats", "Server statistics"),
            ("!vpsinfo [container]", "VPS information"),
            ("!list-all", "List all VPS"),
            ("!restart-vps <container>", "Restart VPS"),
            ("!exec <container> <command>", "Execute command"),
            ("!stop-vps-all", "Stop all VPS"),
            ("!cpu-monitor <status|enable|disable>", "Resource monitor control"),
            ("!clone-vps <container> [new_name]", "Clone VPS"),
            ("!migrate-vps <container> <pool>", "Migrate VPS"),
            ("!vps-stats <container>", "VPS stats"),
            ("!vps-network <container> <action> [value]", "Network management"),
            ("!vps-processes <container>", "List processes"),
            ("!vps-logs <container> [lines]", "Show logs"),
            ("!vps-uptime <container>", "VPS uptime"),
            ("!apply-permissions <container>", "Apply Docker-ready permissions"),
            ("!snapshot <container> [snap_name]", "Create snapshot"),
            ("!list-snapshots <container>", "List snapshots"),
            ("!restore-snapshot <container> <snap_name>", "Restore snapshot"),
            ("!thresholds", "View resource thresholds"),
            ("!set-threshold <cpu> <ram>", "Set resource thresholds"),
            ("!set-status <type> <name>", "Set bot status")
        ]
        admin_commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in admin_commands])
        add_field(embed, "🛡️ Admin Commands", admin_commands_text, False)
        await ctx.send(embed=embed)
    if is_user_main_admin:
        embed = create_embed(f"🆘 {BRAND_NAME} Command Help - Main Admin Commands", f"{BRAND_NAME} VPS Manager Commands:", 0x2b2d31)
        main_admin_commands = [
            ("!admin-add @user", "Add admin"),
            ("!admin-remove @user", "Remove admin"),
            ("!admin-list", "List admins")
        ]
        main_admin_commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in main_admin_commands])
        add_field(embed, "👑 Main Admin Commands", main_admin_commands_text, False)
        embed.set_footer(text=f"{BRAND_NAME} VPS Manager • Auto-suspend high-usage only • Whitelist support • Multi-OS • Enhanced monitoring • Docker-ready VPS • Snapshots")
        await ctx.send(embed=embed)

# Command aliases for typos
@bot.command(name='mangage')
async def manage_typo(ctx):
    await ctx.send(embed=create_info_embed("Command Correction", f"Did you mean `!manage`? Use the correct {BRAND_NAME} command."))

@bot.command(name='stats')
async def stats_alias(ctx):
    if str(ctx.author.id) == str(MAIN_ADMIN_ID) or str(ctx.author.id) in admin_data.get("admins", []):
        await server_stats(ctx)
    else:
        await ctx.send(embed=create_error_embed("Access Denied", "This XeloraCloud command requires admin privileges."))

@bot.command(name='info')
async def info_alias(ctx, user: discord.Member = None):
    if str(ctx.author.id) == str(MAIN_ADMIN_ID) or str(ctx.author.id) in admin_data.get("admins", []):
        if user:
            await user_info(ctx, user)
        else:
            await ctx.send(embed=create_error_embed("Usage", "Please specify a user: `!info @user`"))
    else:
        await ctx.send(embed=create_error_embed("Access Denied", "This XeloraCloud command requires admin privileges."))

# Run the bot
# ================================
# SLASH COMMANDS SECTION
# ================================

@bot.tree.command(name="ping", description="Check bot latency and status")
async def slash_ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    embed = create_success_embed("Pong!", f"{BRAND_NAME} Bot latency: {latency}ms")
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="myvps", description="View your VPS list and status")
async def slash_myvps(interaction: discord.Interaction):
    user_id = str(interaction.user.id)
    vps_list = vps_data.get(user_id, [])
    if not vps_list:
        embed = create_error_embed("No VPS Found", f"You don't have any {BRAND_NAME} VPS. Contact an admin to create one.")
        add_field(embed, "Quick Actions", f"• `/manage` - Manage VPS\n• Contact {BRAND_NAME} admin for VPS creation", False)
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    embed = create_info_embed(f"My {BRAND_NAME} VPS", "")
    text = []
    for i, vps in enumerate(vps_list):
        status = vps.get('status', 'unknown').upper()
        if vps.get('suspended', False):
            status += " (SUSPENDED)"
        if vps.get('whitelisted', False):
            status += " (WHITELISTED)"
        config = vps.get('config', 'Custom')
        text.append(f"**VPS {i+1}:** `{vps['container_name']}` - {status} - {config}")
    add_field(embed, "Your VPS", "\n".join(text), False)
    add_field(embed, "Actions", "Use `/manage` to start/stop/reinstall", False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="manage", description="Manage your VPS (start, stop, SSH, etc.)")
async def slash_manage(interaction: discord.Interaction):
    user_id = str(interaction.user.id)
    vps_list = vps_data.get(user_id, [])
    if not vps_list:
        embed = create_error_embed("No VPS Found", f"You don't have any {BRAND_NAME} VPS. Contact an admin to create one.")
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    view = ManageView(user_id, vps_list, is_admin=str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID))
    embed = await view.get_initial_embed()
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

@bot.tree.command(name="vpsinfo", description="Get detailed information about a specific VPS")
@app_commands.describe(vps_name="Name of the VPS container to check")
async def slash_vpsinfo(interaction: discord.Interaction, vps_name: str):
    user_id = str(interaction.user.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    # Find VPS
    found_vps = None
    owner_id = None
    
    for uid, vps_list in vps_data.items():
        for vps in vps_list:
            if vps['container_name'] == vps_name:
                if uid == user_id or is_admin:
                    found_vps = vps
                    owner_id = uid
                    break
        if found_vps:
            break
    
    if not found_vps:
        await interaction.response.send_message(embed=create_error_embed("VPS Not Found", f"No VPS found with name `{vps_name}` or you don't have access."), ephemeral=True)
        return
    
    # Get live stats
    container_name = found_vps['container_name']
    status = await get_container_status(container_name)
    cpu_usage = await get_container_cpu(container_name)
    memory_usage = await get_container_memory(container_name)
    disk_usage = await get_container_disk(container_name)
    uptime = await get_container_uptime(container_name)
    
    # Create info embed
    embed = create_info_embed(f"{BRAND_NAME} VPS Information", f"Details for `{container_name}`")
    
    # Basic info
    basic_info = f"**Container:** `{container_name}`\n"
    basic_info += f"**Status:** `{status.upper()}`\n"
    basic_info += f"**Configuration:** {found_vps.get('config', 'Custom')}\n"
    basic_info += f"**OS:** {found_vps.get('os_version', 'ubuntu:22.04')}\n"
    basic_info += f"**Created:** {found_vps.get('created_at', 'Unknown')[:10]}"
    add_field(embed, "📋 Basic Info", basic_info, False)
    
    # Resources
    resource_info = f"**RAM:** {found_vps['ram']}\n"
    resource_info += f"**CPU:** {found_vps['cpu']} Cores\n"
    resource_info += f"**Storage:** {found_vps['storage']}"
    add_field(embed, "🔧 Allocated Resources", resource_info, True)
    
    # Live stats
    live_stats = f"**CPU Usage:** {cpu_usage}\n"
    live_stats += f"**Memory:** {memory_usage}\n"
    live_stats += f"**Disk:** {disk_usage}\n"
    live_stats += f"**Uptime:** {uptime}"
    add_field(embed, "📊 Live Stats", live_stats, True)
    
    # Status indicators
    status_info = ""
    if found_vps.get('suspended', False):
        status_info += "⚠️ **SUSPENDED**\n"
    if found_vps.get('whitelisted', False):
        status_info += "✅ **WHITELISTED**\n"
    if not status_info:
        status_info = "✅ **ACTIVE**"
    add_field(embed, "🚦 Status", status_info, True)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="help", description="Show all available commands and their usage")
async def slash_help(interaction: discord.Interaction):
    user_id = str(interaction.user.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    embed = create_info_embed(f"{BRAND_NAME} Bot Commands", f"Available commands for {BRAND_NAME} VPS management")
    
    # User commands
    user_cmds = "• `/ping` - Check bot status\n"
    user_cmds += "• `/myvps` - View your VPS list\n"
    user_cmds += "• `/manage` - Manage your VPS (start/stop/SSH)\n"
    user_cmds += "• `/vpsinfo <name>` - Get detailed VPS info\n"
    user_cmds += "• `/help` - Show this help menu"
    add_field(embed, "👤 User Commands", user_cmds, False)
    
    # Legacy prefix commands
    legacy_cmds = "• `!myvps` - View your VPS\n"
    legacy_cmds += "• `!manage` - Manage VPS\n"
    legacy_cmds += "• `!ping` - Bot status\n"
    legacy_cmds += "• `!help` - Full command list"
    add_field(embed, "🔧 Legacy Commands (! prefix)", legacy_cmds, False)
    
    if is_admin:
        admin_cmds = "• `/create <ram> <cpu> <disk> <user>` - Create VPS\n"
        admin_cmds += "• `/serverstats` - Server statistics\n"
        admin_cmds += "• `/listall` - List all VPS\n"
        admin_cmds += "• `!admin-add/remove` - Manage admins"
        add_field(embed, "🛡️ Admin Commands", admin_cmds, False)
    
    # Tips
    tips = f"💡 **Tips:**\n"
    tips += f"• Use slash commands (/) for better experience\n"
    tips += f"• Most commands work in DMs for privacy\n"
    tips += f"• Contact {BRAND_NAME} admin for VPS creation\n"
    tips += f"• Use SSH button in `/manage` for terminal access"
    add_field(embed, "💡 Tips & Info", tips, False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# Admin slash commands
@bot.tree.command(name="create", description="[ADMIN] Create a new VPS for a user")
@app_commands.describe(
    ram="RAM in GB",
    cpu="Number of CPU cores", 
    disk="Disk space in GB",
    user="User to create VPS for"
)
async def slash_create(interaction: discord.Interaction, ram: int, cpu: int, disk: int, user: discord.Member):
    user_id = str(interaction.user.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    if not is_admin:
        await interaction.response.send_message(embed=create_error_embed("Access Denied", f"You need admin permissions. Contact {BRAND_NAME} support."), ephemeral=True)
        return
    
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await interaction.response.send_message(embed=create_error_embed("Invalid Specs", "RAM, CPU, and Disk must be positive integers."), ephemeral=True)
        return
    
    embed = create_info_embed("VPS Creation", f"Creating VPS for {user.mention} with {ram}GB RAM, {cpu} CPU cores, {disk}GB Disk.\nSelect OS below.")
    view = OSSelectView(ram, cpu, disk, user, interaction)
    await interaction.response.send_message(embed=embed, view=view)

@bot.tree.command(name="serverstats", description="[ADMIN] View server statistics and resource usage")
async def slash_serverstats(interaction: discord.Interaction):
    user_id = str(interaction.user.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    if not is_admin:
        await interaction.response.send_message(embed=create_error_embed("Access Denied", f"You need admin permissions. Contact {BRAND_NAME} support."), ephemeral=True)
        return
    
    # Get server stats
    total_vps = sum(len(vps_list) for vps_list in vps_data.values())
    active_vps = 0
    suspended_vps = 0
    
    for vps_list in vps_data.values():
        for vps in vps_list:
            if vps.get('status') == 'running':
                active_vps += 1
            if vps.get('suspended'):
                suspended_vps += 1
    
    cpu_usage = get_cpu_usage()
    ram_usage = get_ram_usage()
    uptime = get_uptime()
    
    embed = create_info_embed(f"{BRAND_NAME} Server Statistics", "Current server status and resource usage")
    
    # VPS Stats
    vps_stats = f"**Total VPS:** {total_vps}\n"
    vps_stats += f"**Active VPS:** {active_vps}\n"
    vps_stats += f"**Suspended VPS:** {suspended_vps}\n"
    vps_stats += f"**Users:** {len(vps_data)}"
    add_field(embed, "📊 VPS Statistics", vps_stats, True)
    
    # Resource usage
    resource_stats = f"**CPU Usage:** {cpu_usage:.1f}%\n"
    resource_stats += f"**RAM Usage:** {ram_usage:.1f}%\n"
    resource_stats += f"**CPU Threshold:** {CPU_THRESHOLD}%\n"
    resource_stats += f"**RAM Threshold:** {RAM_THRESHOLD}%"
    add_field(embed, "🔧 Host Resources", resource_stats, True)
    
    # System info
    system_info = f"**Uptime:** {uptime}\n"
    system_info += f"**Storage Pool:** {DEFAULT_STORAGE_POOL}\n"
    system_info += f"**Monitor Active:** {'✅ Yes' if resource_monitor_active else '❌ No'}"
    add_field(embed, "🖥️ System Info", system_info, False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="listall", description="[ADMIN] List all VPS on the server")
async def slash_listall(interaction: discord.Interaction):
    user_id = str(interaction.user.id)
    is_admin = str(user_id) in admin_data.get("admins", []) or str(user_id) == str(MAIN_ADMIN_ID)
    
    if not is_admin:
        await interaction.response.send_message(embed=create_error_embed("Access Denied", f"You need admin permissions. Contact {BRAND_NAME} support."), ephemeral=True)
        return
    
    if not vps_data:
        await interaction.response.send_message(embed=create_error_embed("No VPS Found", "No VPS are currently registered."), ephemeral=True)
        return
    
    embed = create_info_embed(f"{BRAND_NAME} All VPS", "Complete list of all VPS on the server")
    
    for user_id, vps_list in vps_data.items():
        try:
            user = await bot.fetch_user(int(user_id))
            username = f"{user.display_name} ({user.name})"
        except:
            username = f"User ID: {user_id}"
        
        user_vps = []
        for i, vps in enumerate(vps_list):
            status = vps.get('status', 'unknown').upper()
            if vps.get('suspended'):
                status += " (SUSPENDED)"
            if vps.get('whitelisted'):
                status += " (WHITELISTED)"
            user_vps.append(f"VPS {i+1}: `{vps['container_name']}` - {status}")
        
        add_field(embed, f"👤 {username}", "\n".join(user_vps), False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

if __name__ == "__main__":
    if DISCORD_TOKEN:
        bot.run(DISCORD_TOKEN)
    else:
        logger.error("No Discord token found in DISCORD_TOKEN environment variable.")