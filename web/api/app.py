#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RaspPunzel Dashboard Backend API - Version finale complète
Toutes les fonctionnalités: Ligolo-ng, WiFi AP, Pentest Adapters
"""

import os
import sys
import json
import subprocess
import re
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import psutil
from functools import wraps
import hashlib

app = Flask(__name__, template_folder='/opt/rasppunzel/web')
app.config['SECRET_KEY'] = 'rasppunzel-secret-key-2025'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

AUTH_CONFIG = {
    'username': 'admin',
    'password_hash': '',
    'session_timeout': 480,
    'is_default_password': True  # Flag pour détecter si le mot de passe par défaut est utilisé
}

# =================================================================================================
# Authentification
# =================================================================================================

def load_auth_config():
    """Charge la configuration d'authentification"""
    try:
        config_file = '/opt/rasppunzel/config/auth.json'
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                AUTH_CONFIG['username'] = config.get('username', 'admin')
                AUTH_CONFIG['password_hash'] = config.get('password_hash', '')
                AUTH_CONFIG['is_default_password'] = config.get('is_default_password', True)
        else:
            default_password = 'rasppunzel'
            AUTH_CONFIG['password_hash'] = hashlib.sha256(default_password.encode()).hexdigest()
            AUTH_CONFIG['is_default_password'] = True
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump({
                    'username': AUTH_CONFIG['username'],
                    'password_hash': AUTH_CONFIG['password_hash'],
                    'is_default_password': AUTH_CONFIG['is_default_password']
                }, f, indent=2)
            os.chmod(config_file, 0o600)
    except Exception as e:
        print(f"[!] Erreur chargement config auth: {e}")
        default_password = 'rasppunzel'
        AUTH_CONFIG['password_hash'] = hashlib.sha256(default_password.encode()).hexdigest()
        AUTH_CONFIG['is_default_password'] = True


def save_auth_config():
    """Sauvegarde la configuration d'authentification"""
    try:
        config_file = '/opt/rasppunzel/config/auth.json'
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump({
                'username': AUTH_CONFIG['username'],
                'password_hash': AUTH_CONFIG['password_hash'],
                'is_default_password': AUTH_CONFIG['is_default_password']
            }, f, indent=2)
        os.chmod(config_file, 0o600)
        return True
    except Exception as e:
        print(f"[!] Erreur sauvegarde config auth: {e}")
        return False

def verify_password(password, password_hash):
    """Vérifie un mot de passe contre son hash"""
    return hashlib.sha256(password.encode()).hexdigest() == password_hash

def login_required(f):
    """Décorateur pour vérifier l'authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('index'))
        
        if 'login_time' in session:
            login_time = datetime.fromisoformat(session['login_time'])
            if datetime.now() - login_time > timedelta(minutes=AUTH_CONFIG['session_timeout']):
                session.clear()
                if request.is_json:
                    return jsonify({'success': False, 'error': 'Session expired'}), 401
                return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

# =================================================================================================
# Routes Web
# =================================================================================================

@app.route('/')
def index():
    """Page de connexion"""
    if 'authenticated' in session and session['authenticated']:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Endpoint de connexion"""
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
            
            # Vérifier si c'est le mot de passe par défaut
            redirect_url = '/dashboard'
            if AUTH_CONFIG.get('is_default_password', False):
                redirect_url = '/change-password?first_login=true'
            
            return jsonify({
                'success': True,
                'message': 'Connexion réussie',
                'redirect': redirect_url,
                'require_password_change': AUTH_CONFIG.get('is_default_password', False)
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


@app.route('/change-password')
@login_required
def change_password_page():
    """Page de changement de mot de passe"""
    return render_template('change-password.html')


@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    """Change le mot de passe de l'utilisateur"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({
                'success': False,
                'error': 'Tous les champs sont requis'
            }), 400
        
        # Vérifier le mot de passe actuel
        if not verify_password(current_password, AUTH_CONFIG['password_hash']):
            return jsonify({
                'success': False,
                'error': 'Mot de passe actuel incorrect'
            }), 401
        
        # Valider le nouveau mot de passe
        if len(new_password) < 8:
            return jsonify({
                'success': False,
                'error': 'Le mot de passe doit contenir au moins 8 caractères'
            }), 400
        
        if not re.search(r'[A-Z]', new_password):
            return jsonify({
                'success': False,
                'error': 'Le mot de passe doit contenir au moins une majuscule'
            }), 400
        
        if not re.search(r'[a-z]', new_password):
            return jsonify({
                'success': False,
                'error': 'Le mot de passe doit contenir au moins une minuscule'
            }), 400
        
        if not re.search(r'[0-9]', new_password):
            return jsonify({
                'success': False,
                'error': 'Le mot de passe doit contenir au moins un chiffre'
            }), 400
        
        # Vérifier que le nouveau mot de passe est différent
        if verify_password(new_password, AUTH_CONFIG['password_hash']):
            return jsonify({
                'success': False,
                'error': 'Le nouveau mot de passe doit être différent de l\'ancien'
            }), 400
        
        # Mettre à jour le mot de passe
        AUTH_CONFIG['password_hash'] = hashlib.sha256(new_password.encode()).hexdigest()
        AUTH_CONFIG['is_default_password'] = False
        
        # Sauvegarder
        if save_auth_config():
            return jsonify({
                'success': True,
                'message': 'Mot de passe changé avec succès'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Erreur lors de la sauvegarde du mot de passe'
            }), 500
            
    except Exception as e:
        print(f"[!] Erreur change_password: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# =================================================================================================
# Fonctions Ligolo-ng
# =================================================================================================

def check_ligolo_agent_running():
    """Vérifie si l'agent Ligolo est actif"""
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline and any('ligolo-agent' in str(cmd) for cmd in cmdline):
                    return True, proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        print(f"[!] Erreur check process: {e}")
    
    try:
        result = subprocess.run(
            ['lsof', '-i', '-n', '-P'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'ligolo-ag' in line.lower() and 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) > 1:
                        try:
                            pid = int(parts[1])
                            return True, pid
                        except ValueError:
                            pass
    except Exception as e:
        print(f"[!] Erreur check lsof: {e}")
    
    return False, None


def get_ligolo_connection_info():
    """Récupère les informations de connexion de l'agent Ligolo"""
    info = {
        'connected': False,
        'remote_host': None,
        'remote_port': None,
        'local_port': None,
        'pid': None
    }
    
    try:
        result = subprocess.run(
            ['lsof', '-i', '-n', '-P'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'ligolo-ag' in line.lower() and 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        info['connected'] = True
                        info['pid'] = int(parts[1]) if parts[1].isdigit() else None
                        
                        conn_info = parts[8]
                        if '->' in conn_info:
                            local, remote = conn_info.split('->')
                            if ':' in remote:
                                host, port = remote.rsplit(':', 1)
                                info['remote_host'] = host
                                info['remote_port'] = port
                            if ':' in local:
                                _, local_port = local.rsplit(':', 1)
                                info['local_port'] = local_port
                    break
    except Exception as e:
        print(f"[!] Erreur get connection info: {e}")
    
    return info


def get_ligolo_routes():
    """Récupère les routes réseau avec filtrage intelligent"""
    routes = []
    
    try:
        result = subprocess.run(
            ['/usr/sbin/ip', 'route', 'show'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if not parts:
                    continue
                
                route = {
                    'destination': parts[0],
                    'gateway': None,
                    'interface': None,
                    'metric': None,
                    'raw': line.strip(),
                    'type': 'unknown',
                    'scope': None
                }
                
                for i, part in enumerate(parts):
                    if part == 'via' and i + 1 < len(parts):
                        route['gateway'] = parts[i + 1]
                    elif part == 'dev' and i + 1 < len(parts):
                        route['interface'] = parts[i + 1]
                    elif part == 'metric' and i + 1 < len(parts):
                        route['metric'] = parts[i + 1]
                    elif part == 'scope' and i + 1 < len(parts):
                        route['scope'] = parts[i + 1]
                
                if 'ligolo' in line.lower():
                    route['type'] = 'ligolo'
                    route['priority'] = 1
                elif parts[0] == 'default':
                    route['type'] = 'default'
                    route['priority'] = 2
                elif route['scope'] == 'link':
                    route['type'] = 'link'
                    route['priority'] = 4
                elif '/' in parts[0]:
                    route['type'] = 'network'
                    route['priority'] = 3
                else:
                    route['type'] = 'other'
                    route['priority'] = 5
                
                if route['interface'] != 'lo':
                    routes.append(route)
                elif route['type'] == 'ligolo':
                    routes.append(route)
            
            routes.sort(key=lambda x: (x.get('priority', 999), x['destination']))
            
    except Exception as e:
        print(f"[!] Erreur get_ligolo_routes: {e}")
        import traceback
        traceback.print_exc()
    
    return routes


def get_ligolo_config():
    """Récupère la configuration Ligolo-ng"""
    config = {
        'configured': False,
        'proxy_host': None,
        'proxy_port': 443,
        'version': None,
        'installed': False
    }
    
    try:
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
        
        if os.path.exists('/usr/local/bin/ligolo-agent'):
            config['installed'] = True
            try:
                result = subprocess.run(
                    ['/usr/local/bin/ligolo-agent', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    version_match = re.search(r'v?\d+\.\d+\.\d+', result.stdout)
                    if version_match:
                        config['version'] = version_match.group(0)
            except:
                pass
    except Exception as e:
        print(f"[!] Erreur get_ligolo_config: {e}")
    
    return config


def get_ligolo_logs(lines=50):
    """Récupère les logs Ligolo"""
    logs = []
    
    try:
        result = subprocess.run(
            ['/usr/bin/journalctl', '-u', 'ligolo-agent', '-n', str(lines), '--no-pager', '-o', 'short-iso'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    logs.append(line)
        
        if not logs:
            is_running, pid = check_ligolo_agent_running()
            if is_running and pid:
                logs.append(f"Agent Ligolo actif (PID: {pid})")
                conn_info = get_ligolo_connection_info()
                if conn_info['connected']:
                    logs.append(f"Connecté à {conn_info['remote_host']}:{conn_info['remote_port']}")
            else:
                logs.append("Agent Ligolo non actif")
                
    except Exception as e:
        print(f"[!] Erreur get logs: {e}")
        logs.append(f"Erreur: {str(e)}")
    
    return logs


# =================================================================================================
# Fonctions WiFi Access Point
# =================================================================================================

def get_ap_clients():
    """Récupère la liste des clients connectés à l'AP"""
    clients = []
    
    try:
        # Méthode 1: Fichier de leases DHCP
        leases_file = '/var/lib/misc/dnsmasq.leases'
        if os.path.exists(leases_file):
            with open(leases_file, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        clients.append({
                            'mac': parts[1],
                            'ip': parts[2],
                            'hostname': parts[3] if len(parts) > 3 else 'Unknown',
                            'lease_time': parts[0]
                        })
        
        # Méthode 2: ARP table (backup)
        if not clients:
            result = subprocess.run(
                ['/usr/sbin/ip', 'neigh', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '10.0.0.' in line and 'REACHABLE' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            clients.append({
                                'ip': parts[0],
                                'mac': parts[4],
                                'hostname': 'Unknown',
                                'status': parts[2]
                            })
    
    except Exception as e:
        print(f"[!] Erreur get_ap_clients: {e}")
    
    return clients


def get_ap_config():
    """Récupère la configuration de l'Access Point"""
    config = {
        'ssid': 'PWNBOX_ADMIN',
        'interface': None,
        'ip': '10.0.0.1',
        'dhcp_range': '10.0.0.2-10.0.0.30',
        'channel': 11,
        'hidden': True
    }
    
    try:
        hostapd_conf = '/etc/hostapd/hostapd.conf'
        if os.path.exists(hostapd_conf):
            with open(hostapd_conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('ssid='):
                        config['ssid'] = line.split('=', 1)[1]
                    elif line.startswith('interface='):
                        config['interface'] = line.split('=', 1)[1]
                    elif line.startswith('channel='):
                        config['channel'] = int(line.split('=', 1)[1])
                    elif line.startswith('ignore_broadcast_ssid='):
                        config['hidden'] = line.split('=', 1)[1] == '1'
    except Exception as e:
        print(f"[!] Erreur get_ap_config: {e}")
    
    return config


# =================================================================================================
# Fonctions Pentest WiFi Adapters
# =================================================================================================

def get_wifi_adapters():
    """Récupère tous les adapters WiFi disponibles"""
    adapters = {}
    
    try:
        # Lister toutes les interfaces réseau
        for interface, addrs in psutil.net_if_addrs().items():
            # Filtrer les interfaces WiFi
            if interface.startswith('wlan') or interface.startswith('wlx'):
                adapter_info = {
                    'name': interface,
                    'addresses': [],
                    'status': 'down',
                    'mac': None,
                    'mode': 'managed',
                    'chipset': None
                }
                
                # Récupérer les adresses
                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        adapter_info['addresses'].append({
                            'type': 'ipv4',
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
                    elif addr.family == 17:  # MAC
                        adapter_info['mac'] = addr.address
                
                # Statut de l'interface
                stats = psutil.net_if_stats().get(interface)
                if stats:
                    adapter_info['status'] = 'up' if stats.isup else 'down'
                    adapter_info['speed'] = stats.speed
                
                # Mode WiFi (managed/monitor)
                try:
                    iwconfig_result = subprocess.run(
                        ['/usr/sbin/iwconfig', interface],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    
                    if iwconfig_result.returncode == 0:
                        output = iwconfig_result.stdout
                        if 'Mode:Monitor' in output:
                            adapter_info['mode'] = 'monitor'
                        elif 'Mode:Managed' in output:
                            adapter_info['mode'] = 'managed'
                except:
                    pass
                
                # Détecter le chipset
                adapter_info['chipset'] = detect_chipset(interface)
                
                adapters[interface] = adapter_info
    
    except Exception as e:
        print(f"[!] Erreur get_wifi_adapters: {e}")
    
    return adapters


def detect_chipset(interface):
    """Détecte le chipset d'un adapter WiFi"""
    try:
        # Via ethtool
        result = subprocess.run(
            ['/usr/sbin/ethtool', '-i', interface],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.startswith('driver:'):
                    driver = line.split(':', 1)[1].strip()
                    # Mapping des drivers connus
                    chipset_map = {
                        'rtl88x2bu': 'Realtek RTL88x2BU',
                        'rt2800usb': 'Ralink RT2870/RT3070',
                        'rtl8812au': 'Realtek RTL8812AU',
                        'ath9k_htc': 'Atheros AR9271',
                        'mt76x2u': 'MediaTek MT76x2U'
                    }
                    return chipset_map.get(driver, driver)
    except:
        pass
    
    return 'Unknown'


def set_monitor_mode(interface, enable=True):
    """Active ou désactive le mode monitor sur un interface"""
    try:
        # Désactiver l'interface
        subprocess.run(['/usr/sbin/ip', 'link', 'set', interface, 'down'], timeout=5, check=True)
        
        if enable:
            # Activer le mode monitor
            subprocess.run(['/usr/sbin/iw', 'dev', interface, 'set', 'type', 'monitor'], timeout=5, check=True)
        else:
            # Revenir en mode managed
            subprocess.run(['/usr/sbin/iw', 'dev', interface, 'set', 'type', 'managed'], timeout=5, check=True)
        
        # Réactiver l'interface
        subprocess.run(['/usr/sbin/ip', 'link', 'set', interface, 'up'], timeout=5, check=True)
        
        return True
    except Exception as e:
        print(f"[!] Erreur set_monitor_mode: {e}")
        return False


def scan_wifi_networks(interface):
    """Scan les réseaux WiFi disponibles"""
    networks = []
    
    try:
        # S'assurer que l'interface est up
        subprocess.run(['/usr/sbin/ip', 'link', 'set', interface, 'up'], timeout=5)
        
        # Scanner
        result = subprocess.run(
            ['/usr/sbin/iw', 'dev', interface, 'scan'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            current_network = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('BSS '):
                    if current_network:
                        networks.append(current_network)
                    current_network = {
                        'bssid': line.split()[1].rstrip(':'),
                        'ssid': None,
                        'channel': None,
                        'signal': None,
                        'security': []
                    }
                elif 'SSID:' in line:
                    current_network['ssid'] = line.split('SSID:', 1)[1].strip()
                elif 'freq:' in line:
                    freq = int(line.split(':')[1].strip())
                    # Convertir fréquence en canal
                    if 2412 <= freq <= 2484:
                        current_network['channel'] = (freq - 2407) // 5
                    elif 5170 <= freq <= 5825:
                        current_network['channel'] = (freq - 5000) // 5
                elif 'signal:' in line:
                    signal = line.split(':')[1].strip().split()[0]
                    current_network['signal'] = signal
                elif 'WPA' in line:
                    current_network['security'].append('WPA')
                elif 'RSN' in line:
                    current_network['security'].append('WPA2')
            
            if current_network:
                networks.append(current_network)
    
    except Exception as e:
        print(f"[!] Erreur scan_wifi_networks: {e}")
    
    return networks


# =================================================================================================
# Fonctions utilitaires
# =================================================================================================

def is_service_active(service_name):
    """Vérifie si un service systemd est actif"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() == 'active'
    except:
        return False


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


def get_kernel_version():
    """Récupère la version du kernel"""
    try:
        return os.uname().release
    except:
        return "unknown"


# =================================================================================================
# Routes API - Status
# =================================================================================================

@app.route('/api/status')
@login_required
def get_status():
    """Retourne le statut complet du système"""
    try:
        ligolo_running, ligolo_pid = check_ligolo_agent_running()
        ligolo_conn_info = get_ligolo_connection_info()
        
        services_status = {
            'ligolo-agent': ligolo_running,
            'hostapd': is_service_active('hostapd'),
            'dnsmasq': is_service_active('dnsmasq'),
            'ssh': is_service_active('ssh'),
            'rasppunzel-web': True
        }
        
        system_info = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'uptime': get_uptime(),
            'hostname': os.uname().nodename,
            'kernel': get_kernel_version(),
            'network_interfaces': get_network_interfaces()
        }
        
        ligolo_config = get_ligolo_config()
        ligolo_config.update({
            'running': ligolo_running,
            'pid': ligolo_pid,
            'connection': ligolo_conn_info
        })
        
        routes = get_ligolo_routes()
        
        print(f"[DEBUG] Nombre de routes: {len(routes)}")
        if routes:
            print(f"[DEBUG] Première route: {routes[0]}")
        
        return jsonify({
            'success': True,
            'services': services_status,
            'system': system_info,
            'ligolo': ligolo_config,
            'routes': routes,
            'routes_count': len(routes),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[!] Erreur get_status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# =================================================================================================
# Routes API - Ligolo
# =================================================================================================

@app.route('/api/routes')
@login_required
def get_routes_api():
    """Endpoint dédié aux routes"""
    try:
        debug_mode = request.args.get('debug', 'false').lower() == 'true'
        routes = get_ligolo_routes()
        
        if debug_mode:
            return jsonify({
                'success': True,
                'routes': routes,
                'count': len(routes),
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'success': True,
                'routes': routes,
                'timestamp': datetime.now().isoformat()
            })
            
    except Exception as e:
        print(f"[!] Erreur get_routes_api: {e}")
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
            capture_output=True,
            text=True,
            timeout=15
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'message': 'Agent redémarré' if result.returncode == 0 else result.stderr
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# =================================================================================================
# Routes API - WiFi AP
# =================================================================================================

@app.route('/api/ap/clients')
@login_required
def api_get_ap_clients():
    """Liste des clients connectés à l'AP"""
    try:
        clients = get_ap_clients()
        
        return jsonify({
            'success': True,
            'clients': clients,
            'count': len(clients),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/ap/config')
@login_required
def api_get_ap_config():
    """Configuration de l'AP"""
    try:
        config = get_ap_config()
        
        return jsonify({
            'success': True,
            'config': config
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# =================================================================================================
# Routes API - Pentest Adapters
# =================================================================================================

@app.route('/api/adapters')
@login_required
def api_get_adapters():
    """Liste des adapters WiFi"""
    try:
        adapters = get_wifi_adapters()
        
        return jsonify({
            'success': True,
            'adapters': adapters,
            'count': len(adapters),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/adapters/<interface>/monitor', methods=['POST'])
@login_required
def api_toggle_monitor(interface):
    """Active/désactive le mode monitor"""
    try:
        data = request.get_json() or {}
        enable = data.get('enable', True)
        
        success = set_monitor_mode(interface, enable)
        
        return jsonify({
            'success': success,
            'message': f"Mode monitor {'activé' if enable else 'désactivé'}" if success else "Erreur"
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/adapters/<interface>/toggle', methods=['POST'])
@login_required
def api_toggle_interface(interface):
    """Active/désactive une interface"""
    try:
        data = request.get_json() or {}
        enable = data.get('enable', True)
        
        action = 'up' if enable else 'down'
        result = subprocess.run(
            ['/usr/sbin/ip', 'link', 'set', interface, action],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'message': f"Interface {action}" if result.returncode == 0 else result.stderr
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/adapters/<interface>/scan', methods=['POST'])
@login_required
def api_scan_networks(interface):
    """Scan les réseaux WiFi"""
    try:
        networks = scan_wifi_networks(interface)
        
        return jsonify({
            'success': True,
            'networks': networks,
            'count': len(networks),
            'interface': interface,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# =================================================================================================
# Routes API - Services
# =================================================================================================

@app.route('/api/services/start', methods=['POST'])
@login_required
def start_services():
    """Démarre des services système"""
    try:
        data = request.get_json() or {}
        services = data.get('services', ['ligolo-agent', 'hostapd', 'dnsmasq'])
        
        results = []
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'start', service],
                    capture_output=True,
                    text=True,
                    timeout=10
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
                    'error': str(e)
                })
        
        return jsonify({
            'success': all(r['success'] for r in results),
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
    """Arrête des services système"""
    try:
        data = request.get_json() or {}
        services = data.get('services', ['ligolo-agent', 'hostapd', 'dnsmasq'])
        
        results = []
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'stop', service],
                    capture_output=True,
                    text=True,
                    timeout=10
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
                    'error': str(e)
                })
        
        return jsonify({
            'success': all(r['success'] for r in results),
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
    """Redémarre des services système"""
    try:
        data = request.get_json() or {}
        services = data.get('services', ['ligolo-agent', 'hostapd', 'dnsmasq'])
        
        results = []
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'restart', service],
                    capture_output=True,
                    text=True,
                    timeout=15
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
                    'error': str(e)
                })
        
        return jsonify({
            'success': all(r['success'] for r in results),
            'results': results
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# =================================================================================================
# Routes API - Logs & Network
# =================================================================================================

@app.route('/api/logs')
@login_required
def get_logs():
    """Retourne les logs système"""
    try:
        log_type = request.args.get('type', 'ligolo')
        lines = int(request.args.get('lines', 50))
        
        logs_data = {}
        
        if log_type in ['all', 'ligolo']:
            logs_data['ligolo'] = get_ligolo_logs(lines)
        
        if log_type in ['all', 'system']:
            result = subprocess.run(
                ['/usr/bin/journalctl', '-n', str(lines), '--no-pager', '-o', 'short'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logs_data['system'] = [
                    line for line in result.stdout.split('\n') if line.strip()
                ]
        
        if log_type in ['all', 'hostapd']:
            result = subprocess.run(
                ['/usr/bin/journalctl', '-u', 'hostapd', '-n', str(lines), '--no-pager', '-o', 'short'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logs_data['hostapd'] = [
                    line for line in result.stdout.split('\n') if line.strip()
                ]
        
        if log_type in ['all', 'dnsmasq']:
            result = subprocess.run(
                ['/usr/bin/journalctl', '-u', 'dnsmasq', '-n', str(lines), '--no-pager', '-o', 'short'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logs_data['dnsmasq'] = [
                    line for line in result.stdout.split('\n') if line.strip()
                ]
        
        # Si un type spécifique, retourner directement
        if log_type in logs_data:
            return jsonify({
                'success': True,
                'logs': logs_data[log_type]
            })
        
        # Sinon retourner tout
        return jsonify({
            'success': True,
            'logs': logs_data
        })
        
    except Exception as e:
        print(f"[!] Erreur get_logs: {e}")
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
                elif addr.family == 17:  # MAC
                    iface_info['mac'] = addr.address
            
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
        print(f"[!] Erreur get_network_info: {e}")
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
            'ap': get_ap_config(),
            'network': get_network_interfaces(),
            'adapters': get_wifi_adapters(),
            'services': {
                'ligolo-agent': check_ligolo_agent_running()[0],
                'hostapd': is_service_active('hostapd'),
                'dnsmasq': is_service_active('dnsmasq')
            },
            'system': {
                'hostname': os.uname().nodename,
                'kernel': get_kernel_version(),
                'uptime': get_uptime()
            },
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


# =================================================================================================
# WebSocket
# =================================================================================================

@socketio.on('connect')
def handle_connect():
    """Gestion des connexions WebSocket"""
    if 'authenticated' not in session or not session['authenticated']:
        return False
    emit('connected', {'message': 'Connexion WebSocket établie'})


@socketio.on('disconnect')
def handle_disconnect():
    """Gestion des déconnexions WebSocket"""
    pass


@socketio.on('request_status')
def handle_request_status():
    """Envoi du statut via WebSocket"""
    try:
        ligolo_running, ligolo_pid = check_ligolo_agent_running()
        
        emit('status_update', {
            'ligolo_running': ligolo_running,
            'ligolo_pid': ligolo_pid,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        emit('error', {'message': str(e)})


# =================================================================================================
# Main
# =================================================================================================

def run_server(host='0.0.0.0', port=5000, debug=False):
    """Lance le serveur Flask"""
    print(f"[+] RaspPunzel Dashboard Backend v2.1")
    print(f"[+] ================================")
    print(f"[+] Chargement de la configuration...")
    load_auth_config()
    
    print(f"[+] Démarrage du serveur sur {host}:{port}")
    print(f"[+] Interface web: http://{host}:8080")
    print(f"[+] Utilisateur: {AUTH_CONFIG['username']}")
    print(f"[+] Mot de passe par défaut: rasppunzel")
    print(f"[+] ")
    print(f"[+] Fonctionnalités disponibles:")
    print(f"[+]   - Ligolo-ng Management")
    print(f"[+]   - WiFi Access Point Control")
    print(f"[+]   - Pentest WiFi Adapters Management")
    print(f"[+] ")
    
    try:
        socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du serveur...")
        sys.exit(0)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='RaspPunzel Dashboard Server - Multi-feature Pentest Platform'
    )
    parser.add_argument('--host', default='0.0.0.0', help='Adresse d\'écoute')
    parser.add_argument('--port', type=int, default=5000, help='Port d\'écoute')
    parser.add_argument('--debug', action='store_true', help='Mode debug')
    
    args = parser.parse_args()
    run_server(args.host, args.port, args.debug)