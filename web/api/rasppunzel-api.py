#!/usr/bin/env python3
"""
RaspPunzel API Backend
Backend Flask pour contrôler les outils de pentest via interface web
"""

import os
import subprocess
import psutil
import json
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import logging

app = Flask(__name__)
CORS(app)

# Configuration logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration des chemins
TOOLS_DIR = "/opt/rasppunzel-tools"
SCRIPTS_DIR = "/opt/rasppunzel-scripts"
LOG_DIR = "/var/log/rasppunzel"

# Stockage des processus actifs
active_processes = {}
tool_outputs = {}

def run_command(command, background=False, tool_name=None):
    """Exécuter une commande système"""
    try:
        if background:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            if tool_name:
                active_processes[tool_name] = process
                # Démarrer un thread pour capturer la sortie
                threading.Thread(
                    target=capture_output,
                    args=(process, tool_name),
                    daemon=True
                ).start()
            return {'success': True, 'pid': process.pid}
        else:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Command timed out'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def capture_output(process, tool_name):
    """Capturer la sortie d'un processus en arrière-plan"""
    output_lines = []
    try:
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                output_lines.append(line.strip())
                # Garder seulement les 100 dernières lignes
                if len(output_lines) > 100:
                    output_lines = output_lines[-100:]
                tool_outputs[tool_name] = output_lines
    except Exception as e:
        logger.error(f"Erreur capture output pour {tool_name}: {e}")
    finally:
        if tool_name in active_processes:
            del active_processes[tool_name]

# Routes API

@app.route('/api/status', methods=['GET'])
def get_status():
    """Obtenir le statut du système"""
    try:
        # Statut des services
        services_status = {}
        services = ['ssh', 'hostapd', 'dnsmasq', 'nginx']
        
        for service in services:
            result = run_command(f"systemctl is-active {service}")
            services_status[service] = result['stdout'].strip() == 'active'
        
        # Informations système
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Température CPU (Raspberry Pi)
        try:
            temp_result = run_command("vcgencmd measure_temp")
            if temp_result['success']:
                temp_str = temp_result['stdout'].strip()
                temperature = temp_str.replace('temp=', '').replace("'C", '')
            else:
                temperature = "N/A"
        except:
            temperature = "N/A"
        
        # Interfaces réseau
        network_interfaces = []
        for interface, addresses in psutil.net_if_addrs().items():
            for addr in addresses:
                if addr.family == 2:  # IPv4
                    network_interfaces.append({
                        'interface': interface,
                        'ip': addr.address
                    })
        
        return jsonify({
            'success': True,
            'data': {
                'services': services_status,
                'system': {
                    'uptime': time.time() - psutil.boot_time(),
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory': {
                        'total': memory.total,
                        'used': memory.used,
                        'percent': memory.percent
                    },
                    'disk': {
                        'total': disk.total,
                        'used': disk.used,
                        'percent': disk.used / disk.total * 100
                    },
                    'temperature': temperature
                },
                'network': network_interfaces,
                'active_tools': list(active_processes.keys())
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/services/<action>', methods=['POST'])
def manage_services(action):
    """Gérer les services système"""
    try:
        if action == 'start':
            result = run_command(f"{SCRIPTS_DIR}/start-services.sh")
        elif action == 'stop':
            result = run_command(f"{SCRIPTS_DIR}/stop-services.sh")
        elif action == 'restart':
            result = run_command(f"{SCRIPTS_DIR}/service-manager.sh restart")
        else:
            return jsonify({'success': False, 'error': 'Action invalide'}), 400
        
        return jsonify({
            'success': result['success'],
            'message': f"Services {action} {'réussi' if result['success'] else 'échoué'}",
            'output': result.get('stdout', ''),
            'error': result.get('stderr', '')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tools/<tool_name>/run', methods=['POST'])
def run_tool(tool_name):
    """Lancer un outil de pentest"""
    try:
        data = request.get_json() or {}
        target = data.get('target', '')
        options = data.get('options', '')
        background = data.get('background', True)
        
        # Dictionnaire des commandes d'outils
        tool_commands = {
            # Reconnaissance
            'nmap': f"nmap {options} {target}" if target else f"nmap {options}",
            'masscan': f"masscan {options} {target}" if target else f"masscan {options}",
            'kismet': "kismet -c wlan1",
            'airodump': "airodump-ng wlan1mon",
            
            # WiFi Attacks
            'wifite': "wifite --wpa --dict /usr/share/wordlists/rockyou.txt",
            'aircrack': f"aircrack-ng {options} {target}" if target else "aircrack-ng",
            'reaver': "reaver -i wlan1mon -b [TARGET_BSSID] -vv",
            'bully': "bully -d [TARGET_BSSID] wlan1mon",
            
            # Web Security
            'nikto': f"nikto -h {target}" if target else "nikto",
            'gobuster': f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt" if target else "gobuster",
            'sqlmap': f"sqlmap -u '{target}' --batch" if target else "sqlmap",
            
            # Password Attacks
            'hydra': f"hydra {target} {options}" if target else "hydra",
            'john': f"john {options} {target}" if target else "john",
            'hashcat': f"hashcat {options} {target}" if target else "hashcat",
            'medusa': f"medusa {options} -h {target}" if target else "medusa",
            
            # Exploitation
            'msfconsole': "msfconsole -q",
            'bettercap': "bettercap -iface wlan1",
            'ettercap': "ettercap -T -M arp:remote",
            
            # Network Analysis
            'tcpdump': f"tcpdump -i wlan1 {options}",
            'wireshark': "wireshark"
        }
        
        if tool_name not in tool_commands:
            return jsonify({'success': False, 'error': f'Outil {tool_name} non supporté'}), 400
        
        # Vérifier si l'outil est déjà en cours d'exécution
        if tool_name in active_processes:
            return jsonify({
                'success': False, 
                'error': f'{tool_name} est déjà en cours d\'exécution'
            }), 409
        
        command = tool_commands[tool_name]
        
        # Log de lancement
        log_msg = f"[{datetime.now()}] Lancement de {tool_name}: {command}"
        logger.info(log_msg)
        
        # Exécuter la commande
        result = run_command(command, background=background, tool_name=tool_name if background else None)
        
        return jsonify({
            'success': result['success'],
            'tool': tool_name,
            'command': command,
            'background': background,
            'pid': result.get('pid'),
            'output': result.get('stdout', '') if not background else '',
            'error': result.get('stderr', '') if not background else ''
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tools/<tool_name>/stop', methods=['POST'])
def stop_tool(tool_name):
    """Arrêter un outil en cours d'exécution"""
    try:
        if tool_name not in active_processes:
            return jsonify({'success': False, 'error': f'{tool_name} n\'est pas en cours d\'exécution'}), 404
        
        process = active_processes[tool_name]
        process.terminate()
        
        # Attendre un peu puis forcer l'arrêt si nécessaire
        time.sleep(2)
        if process.poll() is None:
            process.kill()
        
        # Nettoyer
        if tool_name in active_processes:
            del active_processes[tool_name]
        if tool_name in tool_outputs:
            del tool_outputs[tool_name]
        
        return jsonify({
            'success': True,
            'message': f'{tool_name} arrêté avec succès'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tools/<tool_name>/output', methods=['GET'])
def get_tool_output(tool_name):
    """Obtenir la sortie d'un outil en cours d'exécution"""
    try:
        if tool_name not in tool_outputs:
            return jsonify({'success': False, 'error': f'Aucune sortie disponible pour {tool_name}'}), 404
        
        lines = request.args.get('lines', 50, type=int)
        output = tool_outputs[tool_name][-lines:] if lines > 0 else tool_outputs[tool_name]
        
        return jsonify({
            'success': True,
            'tool': tool_name,
            'output': output,
            'is_running': tool_name in active_processes,
            'total_lines': len(tool_outputs[tool_name])
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tools/active', methods=['GET'])
def get_active_tools():
    """Obtenir la liste des outils actifs"""
    try:
        active_tools = []
        for tool_name, process in active_processes.items():
            active_tools.append({
                'name': tool_name,
                'pid': process.pid,
                'running_time': time.time() - process.create_time(),
                'output_lines': len(tool_outputs.get(tool_name, []))
            })
        
        return jsonify({
            'success': True,
            'active_tools': active_tools,
            'count': len(active_tools)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/update', methods=['POST'])
def system_update():
    """Mettre à jour le système"""
    try:
        result = run_command(f"{SCRIPTS_DIR}/update-system.sh", background=True, tool_name="system_update")
        
        return jsonify({
            'success': result['success'],
            'message': 'Mise à jour démarrée en arrière-plan',
            'pid': result.get('pid')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logs/<log_type>', methods=['GET'])
def get_logs(log_type):
    """Obtenir les logs système"""
    try:
        lines = request.args.get('lines', 50, type=int)
        
        log_commands = {
            'system': f"journalctl -u rasppunzel-tower -n {lines} --no-pager",
            'hostapd': f"journalctl -u hostapd -n {lines} --no-pager",
            'dnsmasq': f"tail -n {lines} /var/log/dnsmasq.log",
            'nginx': f"tail -n {lines} /var/log/nginx/access.log",
            'rasppunzel': f"tail -n {lines} {LOG_DIR}/access.log"
        }
        
        if log_type not in log_commands:
            return jsonify({'success': False, 'error': f'Type de log {log_type} non supporté'}), 400
        
        result = run_command(log_commands[log_type])
        
        return jsonify({
            'success': result['success'],
            'log_type': log_type,
            'logs': result.get('stdout', '').split('\n') if result['success'] else [],
            'error': result.get('stderr', '')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/network/interfaces', methods=['GET'])
def get_network_interfaces():
    """Obtenir les interfaces réseau"""
    try:
        interfaces = []
        
        # Utiliser ip command pour plus d'informations
        result = run_command("ip addr show")
        if result['success']:
            # Parser basique de la sortie ip addr
            lines = result['stdout'].split('\n')
            current_interface = None
            
            for line in lines:
                line = line.strip()
                if line and line[0].isdigit():
                    # Nouvelle interface
                    parts = line.split(':')
                    if len(parts) >= 2:
                        current_interface = {
                            'name': parts[1].strip(),
                            'addresses': [],
                            'state': 'UP' if 'UP' in line else 'DOWN'
                        }
                        interfaces.append(current_interface)
                elif 'inet ' in line and current_interface:
                    # Adresse IPv4
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            addr = parts[i + 1].split('/')[0]
                            current_interface['addresses'].append(addr)
        
        return jsonify({
            'success': True,
            'interfaces': interfaces
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/network/scan', methods=['POST'])
def network_scan():
    """Scanner le réseau local"""
    try:
        data = request.get_json() or {}
        target = data.get('target', '192.168.10.0/24')
        scan_type = data.get('type', 'ping')
        
        if scan_type == 'ping':
            command = f"nmap -sn {target}"
        elif scan_type == 'port':
            command = f"nmap -F {target}"
        elif scan_type == 'full':
            command = f"nmap -A {target}"
        else:
            return jsonify({'success': False, 'error': 'Type de scan invalide'}), 400
        
        result = run_command(command, background=True, tool_name=f"network_scan_{scan_type}")
        
        return jsonify({
            'success': result['success'],
            'scan_type': scan_type,
            'target': target,
            'pid': result.get('pid'),
            'message': 'Scan démarré en arrière-plan'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/test', methods=['GET'])
def test_api():
    """Test de l'API"""
    return jsonify({
        'success': True,
        'message': 'RaspPunzel API is running!',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0'
    })

# Gestionnaire d'erreurs
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Créer les répertoires nécessaires
    os.makedirs(LOG_DIR, exist_ok=True)
    
    # Configuration Flask
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )