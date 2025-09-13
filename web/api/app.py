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
from flask import Flask, request, jsonify, render_template, Response, session, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import psutil
import signal
from werkzeug.serving import make_server
from functools import wraps

app = Flask(__name__, template_folder='../')
app.config['SECRET_KEY'] = 'rasppunzel-secret-key-2025'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)  # Session expiration
CORS(app)
#socketio = SocketIO(app, cors_allowed_origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
# Configuration d'authentification
AUTH_CONFIG = {
    'username': 'admin',  # Par défaut, sera lu depuis config
    'password_hash': '',  # Hash du mot de passe
    'session_timeout': 480  # 8 heures en minutes
}

# Variables globales pour le suivi des processus
running_processes = {}
system_status = {
    'wifi_ap': False,
    'services': False,
    'guacamole': False
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
            default_password = 'RedTeam2025!'
            AUTH_CONFIG['password_hash'] = hashlib.sha256(default_password.encode()).hexdigest()
    except Exception as e:
        print(f"[!] Erreur chargement config auth: {e}")
        # Fallback sur mot de passe par défaut
        default_password = 'RedTeam2025!'
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
                return jsonify({'error': 'Authentication required', 'redirect': '/login'}), 401
            return redirect(url_for('login'))
        
        # Vérifier l'expiration de session
        if 'login_time' in session:
            login_time = datetime.fromisoformat(session['login_time'])
            if datetime.now() - login_time > timedelta(minutes=AUTH_CONFIG['session_timeout']):
                session.clear()
                if request.is_json:
                    return jsonify({'error': 'Session expired', 'redirect': '/login'}), 401
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if (username == AUTH_CONFIG['username'] and 
            verify_password(password, AUTH_CONFIG['password_hash'])):
            
            session['authenticated'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            session.permanent = True
            
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Identifiants incorrects')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Déconnexion"""
    session.clear()
    return redirect(url_for('login'))

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

@app.route('/')
@login_required
def dashboard():
    """Page principale du dashboard"""
    return render_template('dashboard.html')

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
            'network_interfaces': get_network_interfaces()
        }
        
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
            'running_tools': running_tools,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/tools/<tool_name>/start', methods=['POST'])
@login_required
def start_tool(tool_name):
    """Démarre un outil spécifique"""
    try:
        data = request.get_json() or {}
        args = data.get('args', '')
        
        # Configuration des outils
        tool_configs = {
            'nmap': {
                'command': f'/usr/bin/nmap {args} 2>&1',
                'description': 'Scan réseau avec Nmap'
            },
            'masscan': {
                'command': f'/usr/bin/masscan {args} 2>&1',
                'description': 'Scan rapide avec Masscan'
            },
            'kismet': {
                'command': '/usr/bin/kismet -c wlan1mon --no-ncurses 2>&1',
                'description': 'Monitoring WiFi avec Kismet'
            },
            'airodump': {
                'command': f'/usr/bin/airodump-ng {args} wlan1mon 2>&1',
                'description': 'Capture WiFi avec Airodump'
            },
            'wifite': {
                'command': f'/usr/bin/wifite {args} 2>&1',
                'description': 'Attaque WiFi automatisée'
            },
            'aircrack': {
                'command': f'/usr/bin/aircrack-ng {args} 2>&1',
                'description': 'Crack WPA avec Aircrack'
            },
            'reaver': {
                'command': f'/usr/bin/reaver {args} 2>&1',
                'description': 'Attaque WPS avec Reaver'
            },
            'bully': {
                'command': f'/usr/bin/bully {args} 2>&1',
                'description': 'Attaque WPS avec Bully'
            },
            'nikto': {
                'command': f'/usr/bin/nikto {args} 2>&1',
                'description': 'Scan de vulnérabilités web'
            },
            'gobuster': {
                'command': f'/usr/bin/gobuster {args} 2>&1',
                'description': 'Brute force de répertoires'
            },
            'sqlmap': {
                'command': f'/usr/bin/sqlmap {args} 2>&1',
                'description': 'Test d\'injection SQL'
            },
            'hydra': {
                'command': f'/usr/bin/hydra {args} 2>&1',
                'description': 'Brute force avec Hydra'
            },
            'john': {
                'command': f'/usr/bin/john {args} 2>&1',
                'description': 'Crack de hash avec John'
            },
            'hashcat': {
                'command': f'/usr/bin/hashcat {args} 2>&1',
                'description': 'Crack GPU avec Hashcat'
            },
            'medusa': {
                'command': f'/usr/bin/medusa {args} 2>&1',
                'description': 'Brute force multi-protocole'
            },
            'msfconsole': {
                'command': '/usr/bin/msfconsole -q 2>&1',
                'description': 'Console Metasploit'
            },
            'beef': {
                'command': 'cd /usr/share/beef-xss && ./beef 2>&1',
                'description': 'Framework BeEF'
            },
            'wireshark': {
                'command': '/usr/bin/wireshark 2>&1',
                'description': 'Analyseur de paquets'
            },
            'ettercap': {
                'command': f'/usr/bin/ettercap {args} 2>&1',
                'description': 'Attaque Man-in-the-Middle'
            },
            'bettercap': {
                'command': f'/usr/bin/bettercap {args} 2>&1',
                'description': 'Framework d\'attaque réseau'
            },
            'tcpdump': {
                'command': f'/usr/bin/tcpdump {args} 2>&1',
                'description': 'Capture de paquets'
            }
        }
        
        if tool_name not in tool_configs:
            return jsonify({
                'success': False,
                'error': f'Outil {tool_name} non supporté'
            }), 400
        
        config = tool_configs[tool_name]
        success, message = process_manager.start_process(
            tool_name, 
            config['command'],
            cwd=config.get('cwd')
        )
        
        if success:
            socketio.emit('tool_started', {
                'tool': tool_name,
                'description': config['description'],
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify({
            'success': success,
            'message': message,
            'tool': tool_name,
            'description': config['description']
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/tools/<tool_name>/stop', methods=['POST'])
@login_required
def stop_tool(tool_name):
    """Arrête un outil spécifique"""
    try:
        success, message = process_manager.kill_process(tool_name)
        
        if success:
            socketio.emit('tool_stopped', {
                'tool': tool_name,
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify({
            'success': success,
            'message': message,
            'tool': tool_name
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
        services = ['hostapd', 'dnsmasq', 'ssh']
        results = []
        
        for service in services:
            try:
                result = subprocess.run(['systemctl', 'start', service], 
                                      capture_output=True, text=True, timeout=10)
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
        system_status['services'] = success
        
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
        services = ['hostapd', 'dnsmasq']
        results = []
        
        for service in services:
            try:
                result = subprocess.run(['systemctl', 'stop', service], 
                                      capture_output=True, text=True, timeout=10)
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
        system_status['services'] = not success
        
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
        services = ['hostapd', 'dnsmasq']
        results = []
        
        for service in services:
            try:
                result = subprocess.run(['systemctl', 'restart', service], 
                                      capture_output=True, text=True, timeout=15)
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
        system_status['services'] = success
        
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

@app.route('/api/system/update', methods=['POST'])
@login_required
def update_system():
    """Met à jour le système"""
    try:
        # Lancer le script de mise à jour en arrière-plan
        success, message = process_manager.start_process(
            'system_update',
            '/usr/local/bin/update-system.sh'
        )
        
        return jsonify({
            'success': success,
            'message': message
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
        services = ['hostapd', 'dnsmasq', 'ssh']
        
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

def check_services_status():
    """Vérifie le statut des services"""
    services = ['hostapd', 'dnsmasq', 'ssh', 'guacd', 'tomcat9', 'mysql']
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
        
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    except:
        return "00:00:00"

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