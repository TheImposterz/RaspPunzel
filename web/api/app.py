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
from datetime import datetime
from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import psutil
import signal
from werkzeug.serving import make_server

app = Flask(__name__)
app.config['SECRET_KEY'] = 'rasppunzel-secret-key-2024'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Variables globales pour le suivi des processus
running_processes = {}
system_status = {
    'wifi_ap': False,
    'services': False,
    'guacamole': False
}

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
def dashboard():
    """Page principale du dashboard"""
    return render_template('dashboard.html')

@app.route('/api/status')
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
def start_tool(tool_name):
    """Démarre un outil spécifique"""
    try:
        data = request.get_json() or {}
        args = data.get('args', '')
        
        # Configuration des outils
        tool_configs = {
            'nmap': {
                'command': f'nmap {args} 2>&1',
                'description': 'Scan réseau avec Nmap'
            },
            'masscan': {
                'command': f'masscan {args} 2>&1',
                'description': 'Scan rapide avec Masscan'
            },
            'kismet': {
                'command': 'kismet -c wlan1mon --no-ncurses 2>&1',
                'description': 'Monitoring WiFi avec Kismet'
            },
            'airodump': {
                'command': f'airodump-ng {args} wlan1mon 2>&1',
                'description': 'Capture WiFi avec Airodump'
            },
            'wifite': {
                'command': f'wifite {args} 2>&1',
                'description': 'Attaque WiFi automatisée'
            },
            'aircrack': {
                'command': f'aircrack-ng {args} 2>&1',
                'description': 'Crack WPA avec Aircrack'
            },
            'reaver': {
                'command': f'reaver {args} 2>&1',
                'description': 'Attaque WPS avec Reaver'
            },
            'bully': {
                'command': f'bully {args} 2>&1',
                'description': 'Attaque WPS avec Bully'
            },
            'nikto': {
                'command': f'nikto {args} 2>&1',
                'description': 'Scan de vulnérabilités web'
            },
            'gobuster': {
                'command': f'gobuster {args} 2>&1',
                'description': 'Brute force de répertoires'
            },
            'sqlmap': {
                'command': f'sqlmap {args} 2>&1',
                'description': 'Test d\'injection SQL'
            },
            'hydra': {
                'command': f'hydra {args} 2>&1',
                'description': 'Brute force avec Hydra'
            },
            'john': {
                'command': f'john {args} 2>&1',
                'description': 'Crack de hash avec John'
            },
            'hashcat': {
                'command': f'hashcat {args} 2>&1',
                'description': 'Crack GPU avec Hashcat'
            },
            'medusa': {
                'command': f'medusa {args} 2>&1',
                'description': 'Brute force multi-protocole'
            },
            'msfconsole': {
                'command': 'msfconsole -q 2>&1',
                'description': 'Console Metasploit'
            },
            'beef': {
                'command': 'cd /usr/share/beef-xss && ./beef 2>&1',
                'description': 'Framework BeEF'
            },
            'wireshark': {
                'command': 'wireshark 2>&1',
                'description': 'Analyseur de paquets'
            },
            'ettercap': {
                'command': f'ettercap {args} 2>&1',
                'description': 'Attaque Man-in-the-Middle'
            },
            'bettercap': {
                'command': f'bettercap {args} 2>&1',
                'description': 'Framework d\'attaque réseau'
            },
            'tcpdump': {
                'command': f'tcpdump {args} 2>&1',
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
    print(f"[+] Démarrage du serveur RaspPunzel Dashboard sur {host}:{port}")
    print(f"[+] Interface web accessible sur http://{host}:{port}")
    
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