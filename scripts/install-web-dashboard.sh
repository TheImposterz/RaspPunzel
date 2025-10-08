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
# -*- coding: utf-8 -*-

"""
RaspPunzel Dashboard Backend API
Flask application pour contrôler les outils de sécurité
"""

import os
import sys
import json
import subprocess
import threading
import time
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import psutil
import signal
from functools import wraps

app = Flask(__name__, template_folder='/opt/rasppunzel/web')
app.config['SECRET_KEY'] = 'rasppunzel-secret-key-2025'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configuration d'authentification
AUTH_CONFIG = {
    'username': 'admin',
    'password_hash': '',
    'session_timeout': 480  # 8 heures en minutes
}

# Variables globales pour le suivi des processus
system_status = {
    'ligolo_agent': False,
    'hostapd': False,
    'dnsmasq': False,
    'services': False
}

def load_auth_config():
    """Charge la configuration d'authentification depuis le fichier de config"""
    try:
        config_file = '/opt/rasppunzel/config/auth.json'
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                AUTH_CONFIG['username'] = config.get('username', 'admin')
                AUTH_CONFIG['password_hash'] = config.get('password_hash', '')
        else:
            # Valeurs par défaut si pas de fichier de config
            default_password = 'rasppunzel'
            AUTH_CONFIG['password_hash'] = hashlib.sha256(default_password.encode()).hexdigest()
            
            # Créer le dossier et le fichier de config
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump({
                    'username': AUTH_CONFIG['username'],
                    'password_hash': AUTH_CONFIG['password_hash']
                }, f, indent=2)
            os.chmod(config_file, 0o600)
            
    except Exception as e:
        print(f"[!] Erreur chargement config auth: {e}")
        # Fallback sur mot de passe par défaut
        default_password = 'rasppunzel'
        AUTH_CONFIG['password_hash'] = hashlib.sha256(default_password.encode()).hexdigest()

def hash_password(password):
    """Hash un mot de passe avec SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Vérifie un mot de passe contre son hash"""
    return hashlib.sha256(password.encode()).hexdigest() == password_hash

def login_required(f):
    """Décorateur pour vérifier l'authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Authentication required', 'redirect': '/'}), 401
            return redirect(url_for('login'))
        
        # Vérifier l'expiration de session
        if 'login_time' in session:
            login_time = datetime.fromisoformat(session['login_time'])
            if datetime.now() - login_time > timedelta(minutes=AUTH_CONFIG['session_timeout']):
                session.clear()
                if request.is_json:
                    return jsonify({'success': False, 'error': 'Session expired', 'redirect': '/'}), 401
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Page de connexion (index)"""
    if 'authenticated' in session and session['authenticated']:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Endpoint de connexion (POST uniquement)"""
    try:
        data = request.get_json() or request.form
        username = data.get('username')
        password = data.get('password')
        
        if (username == AUTH_CONFIG['username'] and 
            verify_password(password, AUTH_CONFIG['password_hash'])):
            
            session['authenticated'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            session.permanent = True
            
            return jsonify({
                'success': True,
                'message': 'Connexion réussie',
                'redirect': '/dashboard'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Identifiants incorrects'
            }), 401
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/logout')
def logout():
    """Déconnexion"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Page principale du dashboard"""
    return render_template('dashboard.html')


class ProcessManager:
    """Gestionnaire des processus et outils"""
    
    def __init__(self):
        self.processes = {}
        
    def start_process(self, tool_name, command, cwd=None):
        """Démarre un processus et le suit"""
        try:
            if tool_name in self.processes:
                self.kill_process(tool_name)
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                cwd=cwd,
                preexec_fn=os.setsid
            )
            
            self.processes[tool_name] = {
                'process': process,
                'pid': process.pid,
                'command': command,
                'start_time': datetime.now(),
                'status': 'running'
            }
            
            # Thread pour surveiller la sortie
            thread = threading.Thread(
                target=self._monitor_output,
                args=(tool_name, process)
            )
            thread.daemon = True
            thread.start()
            
            return True, f"Processus {tool_name} démarré (PID: {process.pid})"
            
        except Exception as e:
            return False, f"Erreur lors du démarrage de {tool_name}: {str(e)}"
    
    def kill_process(self, tool_name):
        """Tue un processus"""
        if tool_name in self.processes:
            try:
                process_info = self.processes[tool_name]
                process = process_info['process']
                
                # Tuer le groupe de processus
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                
                # Attendre un peu puis forcer si nécessaire
                time.sleep(2)
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                
                process_info['status'] = 'terminated'
                del self.processes[tool_name]
                
                return True, f"Processus {tool_name} terminé"
                
            except Exception as e:
                return False, f"Erreur lors de l'arrêt de {tool_name}: {str(e)}"
        
        return False, f"Processus {tool_name} non trouvé"
    
    def _monitor_output(self, tool_name, process):
        """Surveille la sortie d'un processus"""
        try:
            for line in iter(process.stdout.readline, ''):
                if line:
                    socketio.emit('terminal_output', {
                        'tool': tool_name,
                        'output': line.strip(),
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Le processus s'est terminé
            if tool_name in self.processes:
                self.processes[tool_name]['status'] = 'finished'
                socketio.emit('process_finished', {
                    'tool': tool_name,
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            socketio.emit('terminal_output', {
                'tool': tool_name,
                'output': f"Erreur de monitoring: {str(e)}",
                'timestamp': datetime.now().isoformat()
            })

# Instance du gestionnaire de processus
process_manager = ProcessManager()


@app.route('/api/status')
@login_required
def get_status():
    """Retourne le statut du système"""
    try:
        # Statut des services système
        services_status = check_services_status()
        
        # Informations système
        system_info = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'uptime': get_uptime(),
            'hostname': os.uname().nodename,
            'network_interfaces': get_network_interfaces()
        }
        
        # Configuration Ligolo
        ligolo_config = get_ligolo_config()
        
        # Routes système
        routes = get_system_routes()
        
        # Processus en cours
        running_tools = {
            name: {
                'pid': info['pid'],
                'status': info['status'],
                'start_time': info['start_time'].isoformat(),
                'command': info['command']
            }
            for name, info in process_manager.processes.items()
        }
        
        return jsonify({
            'success': True,
            'services': services_status,
            'system': system_info,
            'ligolo': ligolo_config,
            'routes': routes,
            'running_tools': running_tools,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/routes')
@login_required
def get_routes():
    """Retourne les routes système (ip route)"""
    try:
        routes = get_system_routes()
        return jsonify({
            'success': True,
            'routes': routes
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/routes/discover', methods=['POST'])
@login_required
def discover_routes():
    """Découvre les routes réseau disponibles"""
    try:
        routes = get_system_routes()
        
        # Émettre via WebSocket
        socketio.emit('routes_discovered', {
            'routes': routes,
            'count': len(routes),
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': True,
            'routes': routes,
            'message': f'{len(routes)} routes découvertes'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/ligolo/restart', methods=['POST'])
@login_required
def restart_ligolo():
    """Redémarre l'agent Ligolo-ng"""
    try:
        result = subprocess.run(
            ['systemctl', 'restart', 'ligolo-agent'],
            capture_output=True, text=True, timeout=15
        )
        
        success = result.returncode == 0
        
        socketio.emit('service_restarted', {
            'service': 'ligolo-agent',
            'success': success,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': success,
            'message': 'Agent redémarré' if success else result.stderr
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/ligolo/configure', methods=['POST'])
@login_required
def configure_ligolo():
    """Reconfigurer l'agent Ligolo (lance le wizard)"""
    try:
        return jsonify({
            'success': True,
            'message': 'Exécutez: sudo configure-ligolo.sh sur le terminal',
            'command': 'sudo configure-ligolo.sh'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/services/start', methods=['POST'])
@login_required
def start_services():
    """Démarre les services système"""
    try:
        services = ['ligolo-agent', 'hostapd', 'dnsmasq']
        results = []
        
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'start', service],
                    capture_output=True, text=True, timeout=10
                )
                results.append({
                    'service': service,
                    'success': result.returncode == 0,
                    'message': result.stderr if result.returncode != 0 else 'Démarré'
                })
            except Exception as e:
                results.append({
                    'service': service,
                    'success': False,
                    'message': str(e)
                })
        
        success = all(r['success'] for r in results)
        
        socketio.emit('services_status_changed', {
            'services': success,
            'details': results,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': success,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/services/stop', methods=['POST'])
@login_required
def stop_services():
    """Arrête les services système"""
    try:
        services = ['ligolo-agent', 'hostapd', 'dnsmasq']
        results = []
        
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'stop', service],
                    capture_output=True, text=True, timeout=10
                )
                results.append({
                    'service': service,
                    'success': result.returncode == 0,
                    'message': result.stderr if result.returncode != 0 else 'Arrêté'
                })
            except Exception as e:
                results.append({
                    'service': service,
                    'success': False,
                    'message': str(e)
                })
        
        success = all(r['success'] for r in results)
        
        socketio.emit('services_status_changed', {
            'services': not success,
            'details': results,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': success,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/services/restart', methods=['POST'])
@login_required
def restart_services():
    """Redémarre les services système"""
    try:
        services = ['ligolo-agent', 'hostapd', 'dnsmasq']
        results = []
        
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'restart', service],
                    capture_output=True, text=True, timeout=15
                )
                results.append({
                    'service': service,
                    'success': result.returncode == 0,
                    'message': result.stderr if result.returncode != 0 else 'Redémarré'
                })
            except Exception as e:
                results.append({
                    'service': service,
                    'success': False,
                    'message': str(e)
                })
        
        success = all(r['success'] for r in results)
        
        socketio.emit('services_status_changed', {
            'services': success,
            'details': results,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': success,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/logs')
@login_required
def get_logs():
    """Retourne les logs système"""
    try:
        logs = []
        
        # Logs des services principaux
        services = ['ligolo-agent', 'hostapd', 'dnsmasq', 'rasppunzel-web']
        
        for service in services:
            try:
                result = subprocess.run(
                    ['journalctl', '-u', service, '-n', '20', '--no-pager'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    logs.extend([
                        {'service': service, 'line': line}
                        for line in result.stdout.split('\n')
                        if line.strip()
                    ])
            except:
                pass
        
        return jsonify({
            'success': True,
            'logs': logs[-100:]  # Limiter à 100 dernières lignes
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/network/info')
@login_required
def get_network_info():
    """Retourne les informations réseau détaillées"""
    try:
        interfaces = {}
        
        for interface, addrs in psutil.net_if_addrs().items():
            iface_info = {'addresses': []}
            for addr in addrs:
                if addr.family == 2:  # AF_INET (IPv4)
                    iface_info['addresses'].append({
                        'type': 'ipv4',
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
            
            # Statut de l'interface
            stats = psutil.net_if_stats().get(interface)
            if stats:
                iface_info['status'] = 'up' if stats.isup else 'down'
                iface_info['speed'] = stats.speed
            
            interfaces[interface] = iface_info
        
        return jsonify({
            'success': True,
            'interfaces': interfaces
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/config/export')
@login_required
def export_config():
    """Exporte la configuration système"""
    try:
        config = {
            'ligolo': get_ligolo_config(),
            'network': get_network_interfaces(),
            'services': check_services_status(),
            'export_date': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'config': config
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def check_services_status():
    """Vérifie le statut des services"""
    services = ['ligolo-agent', 'hostapd', 'dnsmasq', 'ssh', 'rasppunzel-web']
    status = {}
    
    for service in services:
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service],
                capture_output=True, text=True, timeout=5
            )
            status[service] = result.stdout.strip() == 'active'
        except:
            status[service] = False
    
    return status


def get_uptime():
    """Retourne l'uptime du système"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        
        if days > 0:
            return f"{days}d {hours:02d}h{minutes:02d}m"
        else:
            return f"{hours:02d}h{minutes:02d}m"
    except:
        return "unknown"


def get_network_interfaces():
    """Retourne les informations des interfaces réseau"""
    interfaces = {}
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2:  # AF_INET (IPv4)
                    interfaces[interface] = {
                        'ip': addr.address,
                        'netmask': addr.netmask
                    }
                    break
    except:
        pass
    
    return interfaces


def get_system_routes():
    """Récupère les routes système via ip route"""
    routes = []
    try:
        result = subprocess.run(
            ['ip', 'route', 'show'],
            capture_output=True, text=True, timeout=5
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    route = {
                        'destination': parts[0] if parts else '',
                        'gateway': None,
                        'interface': None,
                        'metric': None,
                        'raw': line
                    }
                    
                    # Parser la route
                    for i, part in enumerate(parts):
                        if part == 'via' and i + 1 < len(parts):
                            route['gateway'] = parts[i + 1]
                        elif part == 'dev' and i + 1 < len(parts):
                            route['interface'] = parts[i + 1]
                        elif part == 'metric' and i + 1 < len(parts):
                            route['metric'] = parts[i + 1]
                    
                    routes.append(route)
    except Exception as e:
        print(f"[!] Erreur lors de la récupération des routes: {e}")
    
    return routes


def get_ligolo_config():
    """Récupère la configuration Ligolo-ng"""
    config = {
        'configured': False,
        'proxy_host': None,
        'proxy_port': 443,
        'version': None
    }
    
    try:
        # Lire la config depuis /etc/rasppunzel/ligolo.conf
        config_file = '/etc/rasppunzel/ligolo.conf'
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('LIGOLO_PROXY_HOST='):
                        host = line.split('=', 1)[1].strip('"\'')
                        if host:
                            config['proxy_host'] = host
                            config['configured'] = True
                    elif line.startswith('LIGOLO_PROXY_PORT='):
                        config['proxy_port'] = int(line.split('=', 1)[1].strip('"\''))
                    elif line.startswith('LIGOLO_VERSION='):
                        config['version'] = line.split('=', 1)[1].strip('"\'')
        
        # Vérifier si l'agent est installé
        try:
            result = subprocess.run(
                ['/usr/local/bin/ligolo-agent', '--version'],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                config['installed'] = True
        except:
            config['installed'] = False
            
    except Exception as e:
        print(f"[!] Erreur lecture config Ligolo: {e}")
    
    return config


@socketio.on('connect')
def handle_connect():
    """Gestion des connexions WebSocket"""
    # Vérifier l'auth pour WebSocket
    if 'authenticated' not in session or not session['authenticated']:
        return False
    
    emit('connected', {
        'message': 'Connexion WebSocket établie',
        'timestamp': datetime.now().isoformat()
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Gestion des déconnexions WebSocket"""
    pass


def run_server(host='0.0.0.0', port=5000, debug=False):
    """Lance le serveur Flask"""
    print(f"[+] Chargement de la configuration d'authentification...")
    load_auth_config()
    
    print(f"[+] Démarrage du serveur RaspPunzel Dashboard sur {host}:{port}")
    print(f"[+] Interface web accessible sur http://{host}:{port}")
    print(f"[+] Utilisateur: {AUTH_CONFIG['username']}")
    print(f"[+] Mot de passe par défaut: rasppunzel (à changer après première connexion)")
    
    try:
        socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du serveur...")
        # Tuer tous les processus en cours
        for tool_name in list(process_manager.processes.keys()):
            process_manager.kill_process(tool_name)
        sys.exit(0)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='RaspPunzel Dashboard Server')
    parser.add_argument('--host', default='0.0.0.0', help='Adresse d\'écoute')
    parser.add_argument('--port', type=int, default=5000, help='Port d\'écoute')
    parser.add_argument('--debug', action='store_true', help='Mode debug')
    
    args = parser.parse_args()
    run_server(args.host, args.port, args.debug)
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