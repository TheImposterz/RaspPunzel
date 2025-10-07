#!/bin/bash

# =================================================================================================
# RaspPunzel - Web Dashboard Installation Script
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Load configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "${PROJECT_ROOT}/config.sh" ]]; then
    source "${PROJECT_ROOT}/config.sh"
else
    echo -e "${RED}Error: config.sh not found${NC}"
    exit 1
fi

if [[ "${ENABLE_WEB_DASHBOARD}" != "true" ]]; then
    echo -e "${YELLOW}[~] Web dashboard disabled in config${NC}"
    exit 0
fi

echo -e "${YELLOW}[~] Installing web dashboard...${NC}"

# Install dependencies
echo -e "${YELLOW}[~] Installing system packages...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv nginx > /dev/null

# Create web directory
mkdir -p /opt/rasppunzel/web/api
mkdir -p /opt/rasppunzel/web/static

# Copy web files
if [[ -d "${PROJECT_ROOT}/web" ]]; then
    cp "${PROJECT_ROOT}/web/index.html" /opt/rasppunzel/web/ 2>/dev/null || true
    cp "${PROJECT_ROOT}/web/dashboard.html" /opt/rasppunzel/web/ 2>/dev/null || true
fi

# Create Flask API
cat > /opt/rasppunzel/web/api/app.py <<'PYEOF'
#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request, session, redirect
from flask_socketio import SocketIO, emit
import subprocess
import psutil
import os
from datetime import datetime

app = Flask(__name__, template_folder='/opt/rasppunzel/web')
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

# Simple authentication (CHANGE IN PRODUCTION!)
USERS = {
    'admin': 'rasppunzel'  # Username: admin, Password: rasppunzel
}

@app.route('/')
def index():
    return redirect('/index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if USERS.get(username) == password:
        session['logged_in'] = True
        session['username'] = username
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/status')
def get_status():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        # Check if agent is running
        agent_running = is_service_active('ligolo-agent')
        
        # Check if agent is connected to proxy
        agent_connected = False
        if agent_running:
            # Check logs for connection status
            result = subprocess.run(
                ['journalctl', '-u', 'ligolo-agent', '-n', '10', '--no-pager'],
                capture_output=True, text=True
            )
            agent_connected = 'connected' in result.stdout.lower() or 'session' in result.stdout.lower()
        
        services = {
            'ligolo_agent': agent_running,
            'hostapd': is_service_active('hostapd'),
            'dnsmasq': is_service_active('dnsmasq'),
            'ssh': is_service_active('ssh')
        }
        
        system = {
            'hostname': os.uname().nodename,
            'uptime': get_uptime(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'network_interfaces': get_network_interfaces()
        }
        
        # Get agent configuration
        agent_config = {}
        if os.path.exists('/etc/rasppunzel/agent.conf'):
            with open('/etc/rasppunzel/agent.conf', 'r') as f:
                for line in f:
                    if line.startswith('PROXY_HOST'):
                        agent_config['proxy_host'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('PROXY_PORT'):
                        agent_config['proxy_port'] = line.split('=')[1].strip().strip('"')
        
        # Get version
        if os.path.exists('/opt/rasppunzel/ligolo/VERSION'):
            with open('/opt/rasppunzel/ligolo/VERSION', 'r') as f:
                agent_config['version'] = f.read().strip()
        
        return jsonify({
            'success': True,
            'services': services,
            'system': system,
            'agent_connected': agent_connected,
            'agent_config': agent_config,
            'discovered_networks': []  # Will be populated by discover script
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/services/<action>', methods=['POST'])
def manage_services(action):
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    services = ['ligolo-agent', 'hostapd', 'dnsmasq']
    results = {}
    
    for service in services:
        try:
            subprocess.run(['systemctl', action, service], check=True, capture_output=True)
            results[service] = 'success'
        except subprocess.CalledProcessError:
            results[service] = 'failed'
    
    return jsonify({'success': True, 'results': results})

@app.route('/api/agent/restart', methods=['POST'])
def restart_agent():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        subprocess.run(['systemctl', 'restart', 'ligolo-agent'], check=True)
        return jsonify({'success': True})
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/networks/discover', methods=['POST'])
def discover_networks():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        result = subprocess.run(
            ['bash', '/opt/rasppunzel/scripts/discover-routes.sh', '--json'],
            capture_output=True, text=True, timeout=30
        )
        
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            return jsonify({
                'success': True,
                'networks': data.get('networks', [])
            })
        else:
            return jsonify({'success': False, 'message': 'Discovery failed'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/networks/export')
def export_networks():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        result = subprocess.run(
            ['bash', '/opt/rasppunzel/scripts/discover-routes.sh', '--json'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            return jsonify({
                'success': True,
                'networks': data.get('networks', [])
            })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/logs')
def get_logs():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        result = subprocess.run(
            ['journalctl', '-u', 'ligolo-agent', '-n', '50', '--no-pager'],
            capture_output=True, text=True
        )
        logs = result.stdout.strip().split('\n')
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/network/info')
def network_info():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                status = psutil.net_if_stats()[iface].isup
                interfaces[iface] = {
                    'ip': addr.address,
                    'status': 'up' if status else 'down'
                }
    
    return jsonify({'success': True, 'interfaces': interfaces})

def is_service_active(service):
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service],
            capture_output=True, text=True
        )
        return result.stdout.strip() == 'active'
    except:
        return False

def get_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            hours = int(uptime_seconds // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    except:
        return "Unknown"

def get_network_interfaces():
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                interfaces[iface] = {'ip': addr.address}
    return interfaces

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)
PYEOF

# Create requirements.txt
cat > /opt/rasppunzel/web/api/requirements.txt <<EOF
Flask==3.0.0
Flask-SocketIO==5.3.5
python-socketio==5.10.0
psutil==5.9.6
eventlet==0.33.3
EOF

# Create virtual environment and install dependencies
echo -e "${YELLOW}[~] Installing Python dependencies...${NC}"
cd /opt/rasppunzel/web/api
python3 -m venv venv
source venv/bin/activate
pip3 install --quiet --upgrade pip
pip3 install --quiet -r requirements.txt
deactivate

# Make app executable
chmod +x /opt/rasppunzel/web/api/app.py

# Configure Nginx
echo -e "${YELLOW}[~] Configuring Nginx...${NC}"
cp "${PROJECT_ROOT}/config/nginx-rasppunzel.conf" /etc/nginx/sites-available/rasppunzel 2>/dev/null || \
cat > /etc/nginx/sites-available/rasppunzel <<'NGINXEOF'
server {
    listen 8080 default_server;
    listen [::]:8080 default_server;
    server_name rasppunzel.local;
    root /opt/rasppunzel/web;
    index index.html;
    
    access_log /var/log/nginx/rasppunzel_access.log;
    error_log /var/log/nginx/rasppunzel_error.log;
    
    location = / {
        try_files /index.html =404;
    }
    
    location /api/ {
        proxy_pass http://127.0.0.1:5000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /socket.io/ {
        proxy_pass http://127.0.0.1:5000/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
NGINXEOF

# Enable Nginx site
ln -sf /etc/nginx/sites-available/rasppunzel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
nginx -t

# Create systemd service for Flask
echo -e "${YELLOW}[~] Creating Flask service...${NC}"
cat > /etc/systemd/system/rasppunzel-web.service <<EOF
[Unit]
Description=RaspPunzel Web Dashboard API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/rasppunzel/web/api
Environment="PATH=/opt/rasppunzel/web/api/venv/bin"
ExecStart=/opt/rasppunzel/web/api/venv/bin/python3 /opt/rasppunzel/web/api/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Store credentials
cat > /opt/rasppunzel/web/.credentials <<EOF
RaspPunzel Web Dashboard Credentials
====================================
URL: http://$(hostname -I | awk '{print $1}'):8080
Username: admin
Password: rasppunzel

IMPORTANT: Change these credentials in /opt/rasppunzel/web/api/app.py
Edit the USERS dictionary and restart the service:
  sudo nano /opt/rasppunzel/web/api/app.py
  sudo systemctl restart rasppunzel-web
====================================
EOF
chmod 600 /opt/rasppunzel/web/.credentials

# Enable services
systemctl daemon-reload
systemctl enable rasppunzel-web
systemctl enable nginx

# Restart services
systemctl restart rasppunzel-web
systemctl restart nginx

echo -e "${GREEN}[+] Web dashboard installed${NC}"
echo ""
echo "  URL: http://$(hostname -I | awk '{print $1}'):8080"
echo "  Credentials: cat /opt/rasppunzel/web/.credentials"
echo "  Services:"
echo "    - Flask API: systemctl status rasppunzel-web"
echo "    - Nginx: systemctl status nginx"
echo ""


# Create web directory
mkdir -p /opt/rasppunzel/web/api
mkdir -p /opt/rasppunzel/web/static

# Copy web files
if [[ -d "${PROJECT_ROOT}/web" ]]; then
    cp -r "${PROJECT_ROOT}/web/"* /opt/rasppunzel/web/
fi

# Create Flask API
cat > /opt/rasppunzel/web/api/app.py <<'PYEOF'
#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request, session
from flask_socketio import SocketIO, emit
import subprocess
import psutil
import os
from datetime import datetime

app = Flask(__name__, template_folder='/opt/rasppunzel/web')
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

# Simple authentication
USERS = {'admin': 'rasppunzel'}  # Change in production

@app.route('/')
def index():
    if 'logged_in' not in session:
        return render_template('login.html')
    return render_template('dashboard.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if USERS.get(username) == password:
        session['logged_in'] = True
        session['username'] = username
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/api/status')
def get_status():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        services = {
            'ligolo_proxy': is_service_active('ligolo-proxy'),
            'hostapd': is_service_active('hostapd'),
            'dnsmasq': is_service_active('dnsmasq'),
            'ssh': is_service_active('ssh')
        }
        
        system = {
            'hostname': os.uname().nodename,
            'uptime': get_uptime(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'network_interfaces': get_network_interfaces()
        }
        
        return jsonify({
            'success': True,
            'services': services,
            'system': system,
            'agents': [],  # To be implemented
            'routes': get_routes()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/services/<action>', methods=['POST'])
def manage_services(action):
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    services = ['ligolo-proxy', 'hostapd', 'dnsmasq']
    results = {}
    
    for service in services:
        try:
            subprocess.run(['systemctl', action, service], check=True, capture_output=True)
            results[service] = 'success'
        except subprocess.CalledProcessError:
            results[service] = 'failed'
    
    return jsonify({'success': True, 'results': results})

@app.route('/api/logs')
def get_logs():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        result = subprocess.run(
            ['journalctl', '-u', 'ligolo-proxy', '-n', '50', '--no-pager'],
            capture_output=True, text=True
        )
        logs = result.stdout.strip().split('\n')
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def is_service_active(service):
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service],
            capture_output=True, text=True
        )
        return result.stdout.strip() == 'active'
    except:
        return False

def get_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            hours = int(uptime_seconds // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    except:
        return "Unknown"

def get_network_interfaces():
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                interfaces[iface] = {'ip': addr.address}
    return interfaces

def get_routes():
    try:
        result = subprocess.run(
            ['ip', 'route', 'show'],
            capture_output=True, text=True
        )
        routes = []
        for line in result.stdout.strip().split('\n'):
            if 'ligolo' in line:
                parts = line.split()
                if len(parts) >= 3:
                    routes.append({
                        'network': parts[0],
                        'interface': 'ligolo'
                    })
        return routes
    except:
        return []

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
PYEOF

# Create requirements.txt
cat > /opt/rasppunzel/web/api/requirements.txt <<EOF
Flask==3.0.0
Flask-SocketIO==5.3.5
python-socketio==5.10.0
psutil==5.9.6
eventlet==0.33.3
EOF

# Create virtual environment and install dependencies
echo -e "${YELLOW}[~] Installing Python dependencies...${NC}"
cd /opt/rasppunzel/web/api
python3 -m venv venv
source venv/bin/activate
pip3 install --quiet --upgrade pip
pip3 install --quiet -r requirements.txt
deactivate

# Make app executable
chmod +x /opt/rasppunzel/web/api/app.py

# Create systemd service
echo -e "${YELLOW}[~] Creating web service...${NC}"
cat > /etc/systemd/system/rasppunzel-web.service <<EOF
[Unit]
Description=RaspPunzel Web Dashboard
After=network.target ligolo-proxy.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/rasppunzel/web/api
Environment="PATH=/opt/rasppunzel/web/api/venv/bin"
ExecStart=/opt/rasppunzel/web/api/venv/bin/python3 /opt/rasppunzel/web/api/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Store credentials
cat > /opt/rasppunzel/web/.credentials <<EOF
Web Dashboard Credentials
=========================
URL: http://$(hostname -I | awk '{print $1}'):${WEB_PORT}
Username: ${WEB_USERNAME}
Password: ${WEB_PASSWORD}

CHANGE THESE IN: /opt/rasppunzel/web/api/app.py
EOF
chmod 600 /opt/rasppunzel/web/.credentials

# Enable service
systemctl daemon-reload
systemctl enable rasppunzel-web

echo -e "${GREEN}[+] Web dashboard installed${NC}"
echo ""
echo "  URL: http://$(hostname -I | awk '{print $1}'):${WEB_PORT}"
echo "  Credentials: cat /opt/rasppunzel/web/.credentials"
echo "  Start: systemctl start rasppunzel-web"
echo ""