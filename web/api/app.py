#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RaspPunzel Dashboard Backend API - Version complète CORRIGÉE
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
    'is_default_password': True
}

# =================================================================================================
# Authentification - FONCTIONS COMPLÈTES
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
# Routes Web - COMPLÈTES
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

# =================================================================================================
# Fonctions WiFi Access Point CORRIGÉES
# =================================================================================================

def get_ap_interface():
    """Récupère l'interface utilisée par l'AP depuis la configuration hostapd"""
    try:
        hostapd_conf = '/etc/hostapd/hostapd.conf'
        if os.path.exists(hostapd_conf):
            with open(hostapd_conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('interface='):
                        return line.split('=', 1)[1].strip()
    except Exception as e:
        print(f"[!] Erreur get_ap_interface: {e}")

    # Fallback: chercher dans les scripts d'installation
    try:
        for script_file in ['/opt/rasppunzel/scripts/install-system.sh']:
            if os.path.exists(script_file):
                with open(script_file, 'r') as f:
                    content = f.read()
                    # Chercher la variable d'interface BrosTrend
                    match = re.search(r'WLAN_INTERFACE_BROSTREND_AC1L="([^"]+)"', content)
                    if match:
                        return match.group(1)
    except:
        pass

    return None


def get_ap_network_info():
    """Récupère les informations réseau de l'AP depuis les configurations"""
    network_info = {
        'gateway_ip': None,
        'dhcp_start': None,
        'dhcp_end': None,
        'network_prefix': None,
        'interface': None
    }
    
    try:
        # 1. Récupérer l'interface AP depuis hostapd
        hostapd_conf = '/etc/hostapd/hostapd.conf'
        if os.path.exists(hostapd_conf):
            with open(hostapd_conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('interface='):
                        network_info['interface'] = line.split('=', 1)[1].strip()
                        break
        
        # 2. Récupérer les infos depuis dnsmasq.conf
        dnsmasq_conf = '/etc/dnsmasq.conf'
        if os.path.exists(dnsmasq_conf):
            with open(dnsmasq_conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('dhcp-range='):
                        # Format: dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
                        range_parts = line.split('=', 1)[1].split(',')
                        if len(range_parts) >= 2:
                            network_info['dhcp_start'] = range_parts[0].strip()
                            network_info['dhcp_end'] = range_parts[1].strip()
                            
                            # Calculer le préfixe réseau depuis l'IP de début
                            start_ip_parts = network_info['dhcp_start'].split('.')
                            if len(start_ip_parts) == 4:
                                # Supposer un /24 par défaut, mais on peut améliorer
                                network_info['network_prefix'] = f"{start_ip_parts[0]}.{start_ip_parts[1]}.{start_ip_parts[2]}"
                    
                    elif line.startswith('listen-address='):
                        network_info['gateway_ip'] = line.split('=', 1)[1].strip()
        
        # 3. Si pas de gateway dans dnsmasq, chercher sur l'interface
        if not network_info['gateway_ip'] and network_info['interface']:
            try:
                result = subprocess.run(
                    ['/usr/sbin/ip', 'addr', 'show', network_info['interface']],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'inet ' in line and 'scope global' in line:
                            # Exemple: inet 192.168.4.1/24 scope global wlx...
                            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)(?:/\d+)?', line)
                            if ip_match:
                                network_info['gateway_ip'] = ip_match.group(1)
                                # Déduire le préfixe réseau
                                ip_parts = network_info['gateway_ip'].split('.')
                                if len(ip_parts) == 4:
                                    network_info['network_prefix'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                                break
            except Exception as e:
                print(f"[!] Erreur récupération IP interface: {e}")
        
        # 4. Si toujours pas de préfixe réseau, essayer de le déduire du gateway
        if not network_info['network_prefix'] and network_info['gateway_ip']:
            ip_parts = network_info['gateway_ip'].split('.')
            if len(ip_parts) == 4:
                network_info['network_prefix'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
    
    except Exception as e:
        print(f"[!] Erreur get_ap_network_info: {e}")
    
    return network_info


def is_ip_in_ap_network(ip_address, network_info):
    """Vérifie si une IP appartient au réseau de l'AP"""
    if not network_info['network_prefix'] or not ip_address:
        return False
    
    # Vérifier si l'IP commence par le préfixe réseau
    if ip_address.startswith(network_info['network_prefix'] + '.'):
        # Exclure l'IP du gateway
        if ip_address != network_info['gateway_ip']:
            return True
    
    return False


def get_ap_clients():
    """Récupère la liste des clients connectés à l'AP - VERSION AMÉLIORÉE"""
    clients = []
    
    try:
        # Récupérer les informations réseau de l'AP
        network_info = get_ap_network_info()
        
        if not network_info['network_prefix']:
            print(f"[!] Impossible de déterminer le réseau de l'AP")
            return clients
        
        print(f"[DEBUG] Réseau AP détecté: {network_info['network_prefix']}.x, Gateway: {network_info['gateway_ip']}")
        
        # Méthode 1: Fichiers de leases DHCP
        leases_files = [
            '/var/lib/dhcp/dhcpd.leases',
            '/var/lib/dhcpcd5/dhcpcd.leases', 
            '/var/lib/misc/dnsmasq.leases',
            '/tmp/dhcp.leases',
            '/var/run/dnsmasq.leases'
        ]
        
        found_leases = False
        for leases_file in leases_files:
            if os.path.exists(leases_file):
                try:
                    with open(leases_file, 'r') as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 4:
                                lease_time = parts[0]
                                mac = parts[1]
                                ip = parts[2]
                                hostname = parts[3] if len(parts) > 3 else 'Unknown'
                                
                                # Vérifier si l'IP appartient au réseau de l'AP
                                if is_ip_in_ap_network(ip, network_info):
                                    clients.append({
                                        'mac': mac,
                                        'ip': ip,
                                        'hostname': hostname,
                                        'lease_time': lease_time,
                                        'status': 'active',
                                        'source': 'dhcp_lease'
                                    })
                                    found_leases = True
                    
                    if found_leases:
                        print(f"[DEBUG] Trouvé {len(clients)} clients dans {leases_file}")
                        break  # Si on trouve des leases, pas besoin de chercher ailleurs
                        
                except Exception as e:
                    print(f"[!] Erreur lecture {leases_file}: {e}")
                    continue
        
        # Méthode 2: Table ARP (backup ou complément)
        try:
            result = subprocess.run(
                ['/usr/sbin/ip', 'neigh', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                arp_clients = []
                for line in result.stdout.split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 5:
                        ip = parts[0]
                        status = parts[2] if len(parts) > 2 else 'unknown'
                        
                        # Vérifier si l'IP appartient au réseau de l'AP
                        if is_ip_in_ap_network(ip, network_info):
                            # Chercher l'adresse MAC dans la ligne
                            mac = None
                            interface = None
                            
                            for i, part in enumerate(parts):
                                if ':' in part and len(part.split(':')) == 6:
                                    # Probable adresse MAC
                                    mac = part
                                elif part == 'dev' and i + 1 < len(parts):
                                    interface = parts[i + 1]
                            
                            if mac:
                                # Vérifier si ce client n'est pas déjà dans la liste des leases
                                existing_client = None
                                for client in clients:
                                    if client['mac'] == mac or client['ip'] == ip:
                                        existing_client = client
                                        break
                                
                                if existing_client:
                                    # Mettre à jour le statut ARP
                                    existing_client['arp_status'] = status.lower()
                                    existing_client['interface'] = interface
                                else:
                                    # Nouveau client trouvé via ARP
                                    arp_clients.append({
                                        'ip': ip,
                                        'mac': mac,
                                        'hostname': 'Unknown',
                                        'status': status.lower(),
                                        'interface': interface,
                                        'source': 'arp_table'
                                    })
                
                clients.extend(arp_clients)
                if arp_clients:
                    print(f"[DEBUG] Trouvé {len(arp_clients)} clients supplémentaires via ARP")
        
        except Exception as e:
            print(f"[!] Erreur table ARP: {e}")
        
        # Méthode 3: hostapd_cli (si l'interface est connue)
        if network_info['interface']:
            try:
                result = subprocess.run(
                    ['hostapd_cli', '-i', network_info['interface'], 'all_sta'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    hostapd_clients = []
                    current_mac = None
                    
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        # Détecter les adresses MAC (format: aa:bb:cc:dd:ee:ff)
                        if re.match(r'^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$', line):
                            current_mac = line
                            
                            # Vérifier si ce client n'est pas déjà dans la liste
                            existing_client = None
                            for client in clients:
                                if client['mac'].lower() == current_mac.lower():
                                    existing_client = client
                                    break
                            
                            if not existing_client:
                                hostapd_clients.append({
                                    'mac': current_mac,
                                    'ip': 'Unknown',
                                    'hostname': 'Unknown', 
                                    'status': 'connected',
                                    'source': 'hostapd'
                                })
                    
                    clients.extend(hostapd_clients)
                    if hostapd_clients:
                        print(f"[DEBUG] Trouvé {len(hostapd_clients)} clients supplémentaires via hostapd")
            
            except Exception as e:
                print(f"[!] Erreur hostapd_cli: {e}")
        
        # Dédupliquer et nettoyer la liste finale
        unique_clients = []
        seen_macs = set()
        seen_ips = set()
        
        for client in clients:
            # Identifier de manière unique par MAC ou IP
            identifier = client.get('mac', '').lower() or client.get('ip', '')
            
            if identifier and identifier not in seen_macs and identifier not in seen_ips:
                if client.get('mac'):
                    seen_macs.add(client['mac'].lower())
                if client.get('ip'):
                    seen_ips.add(client['ip'])
                unique_clients.append(client)
        
        print(f"[DEBUG] Total final: {len(unique_clients)} clients uniques")
        return unique_clients
    
    except Exception as e:
        print(f"[!] Erreur get_ap_clients: {e}")
        import traceback
        traceback.print_exc()
    
    return clients

def get_ap_config():
    """Récupère la configuration complète de l'Access Point depuis les fichiers système"""
    config = {
        'ssid': None,
        'interface': None,
        'ip_gateway': None,
        'dhcp_range': None,
        'channel': None,
        'hidden': False,
        'security': None,
        'encryption': None,
        'password_set': False,
        'country_code': None,
        'hw_mode': None,
        'hostapd_status': False,
        'dnsmasq_status': False,
        'interface_status': None,
        'broadcast_ssid': True,
        'wpa_version': None,
        'dhcp_lease_time': None,
        'dns_servers': []
    }
    
    try:
        # ===== Configuration hostapd =====
        hostapd_conf = '/etc/hostapd/hostapd.conf'
        if os.path.exists(hostapd_conf):
            with open(hostapd_conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    # Ignorer les commentaires et lignes vides
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Paramètres de base
                        if key == 'ssid':
                            config['ssid'] = value
                        elif key == 'interface':
                            config['interface'] = value
                        elif key == 'channel':
                            try:
                                config['channel'] = int(value)
                            except ValueError:
                                config['channel'] = None
                        elif key == 'hw_mode':
                            config['hw_mode'] = value
                        elif key == 'country_code':
                            config['country_code'] = value
                        
                        # Sécurité
                        elif key == 'ignore_broadcast_ssid':
                            config['hidden'] = value == '1'
                            config['broadcast_ssid'] = value != '1'
                        elif key == 'wpa':
                            if value == '1':
                                config['wpa_version'] = 'WPA'
                                config['security'] = 'WPA'
                            elif value == '2':
                                config['wpa_version'] = 'WPA2'
                                config['security'] = 'WPA2'
                            elif value == '3':
                                config['wpa_version'] = 'WPA/WPA2'
                                config['security'] = 'WPA/WPA2'
                        elif key == 'wpa_key_mgmt':
                            if 'WPA-PSK' in value:
                                config['security'] = config.get('security', 'WPA') + '-PSK'
                        elif key == 'wpa_pairwise' or key == 'rsn_pairwise':
                            config['encryption'] = value
                        elif key == 'wpa_passphrase':
                            config['password_set'] = bool(value)
                        elif key == 'auth_algs':
                            if value == '1':
                                if not config['security']:
                                    config['security'] = 'Open'
        
        # Si pas de sécurité détectée et pas de WPA, probablement ouvert
        if not config['security']:
            config['security'] = 'Open'
        
        # ===== Configuration dnsmasq =====
        dnsmasq_conf = '/etc/dnsmasq.conf'
        if os.path.exists(dnsmasq_conf):
            with open(dnsmasq_conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    # Ignorer les commentaires et lignes vides
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Plage DHCP
                        if key == 'dhcp-range':
                            # Formats possibles:
                            # dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,12h
                            # dhcp-range=192.168.4.2,192.168.4.20,12h
                            # dhcp-range=interface:wlan0,192.168.4.2,192.168.4.20,12h
                            
                            range_parts = value.split(',')
                            
                            # Si premier élément contient "interface:", l'ignorer
                            if range_parts[0].startswith('interface:'):
                                range_parts = range_parts[1:]
                            
                            if len(range_parts) >= 2:
                                start_ip = range_parts[0].strip()
                                end_ip = range_parts[1].strip()
                                config['dhcp_range'] = f"{start_ip}-{end_ip}"
                                
                                # Extraire le temps de lease si présent
                                for part in range_parts[2:]:
                                    if 'h' in part or 'm' in part or 'd' in part:
                                        config['dhcp_lease_time'] = part.strip()
                                        break
                        
                        # Adresse d'écoute (IP du gateway)
                        elif key == 'listen-address':
                            config['ip_gateway'] = value
                        
                        # Interface
                        elif key == 'interface':
                            if not config['interface']:  # Priorité à hostapd
                                config['interface'] = value
                        
                        # Serveurs DNS
                        elif key == 'server':
                            if value not in config['dns_servers']:
                                config['dns_servers'].append(value)
                        elif key == 'dhcp-option' and value.startswith('6,'):
                            # dhcp-option=6,8.8.8.8,8.8.4.4
                            dns_ips = value[2:].split(',')
                            for dns_ip in dns_ips:
                                dns_ip = dns_ip.strip()
                                if dns_ip and dns_ip not in config['dns_servers']:
                                    config['dns_servers'].append(dns_ip)
        
        # ===== Récupération de l'IP du gateway depuis l'interface =====
        if not config['ip_gateway'] and config['interface']:
            try:
                result = subprocess.run(
                    ['/usr/sbin/ip', 'addr', 'show', config['interface']],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'inet ' in line and 'scope global' in line:
                            # Exemple: inet 192.168.4.1/24 scope global wlx...
                            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)(?:/(\d+))?', line)
                            if ip_match:
                                config['ip_gateway'] = ip_match.group(1)
                                break
            except Exception as e:
                print(f"[!] Erreur récupération IP interface: {e}")
        
        # ===== Statut de l'interface =====
        if config['interface']:
            try:
                result = subprocess.run(
                    ['/usr/sbin/ip', 'link', 'show', config['interface']],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    if 'state UP' in result.stdout:
                        config['interface_status'] = 'up'
                    elif 'state DOWN' in result.stdout:
                        config['interface_status'] = 'down'
                    else:
                        config['interface_status'] = 'unknown'
                else:
                    config['interface_status'] = 'not_found'
            except Exception as e:
                print(f"[!] Erreur statut interface: {e}")
                config['interface_status'] = 'error'
        
        # ===== Statut des services =====
        config['hostapd_status'] = is_service_active('hostapd')
        config['dnsmasq_status'] = is_service_active('dnsmasq')
        
        # ===== Validation et nettoyage =====
        # Si pas d'interface trouvée, essayer de la détecter
        if not config['interface']:
            try:
                # Chercher une interface WiFi USB active
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'wlx' in line or 'wlan' in line:
                            interface = line.split()[0]
                            if interface and interface != 'wlan0':  # Éviter la WiFi intégrée
                                config['interface'] = interface
                                break
            except:
                pass
        
        # Logs de debug
        print(f"[DEBUG] Configuration AP détectée:")
        print(f"  SSID: {config['ssid']}")
        print(f"  Interface: {config['interface']} ({config['interface_status']})")
        print(f"  Gateway: {config['ip_gateway']}")
        print(f"  DHCP: {config['dhcp_range']}")
        print(f"  Canal: {config['channel']}")
        print(f"  Sécurité: {config['security']}")
        print(f"  Services: hostapd={config['hostapd_status']}, dnsmasq={config['dnsmasq_status']}")
        
    except Exception as e:
        print(f"[!] Erreur get_ap_config: {e}")
        import traceback
        traceback.print_exc()
    
    return config


def get_real_service_status():
    """Récupère le statut réel des services avec vérifications multiples"""
    services_status = {}

    # Liste des services à vérifier
    services = ['hostapd', 'dnsmasq', 'ligolo-agent', 'ssh']

    for service in services:
        status = {
            'active': False,
            'enabled': False,
            'pid': None,
            'description': None
        }

        try:
            # Vérifier si le service est actif
            result = subprocess.run(
                ['/usr/bin/systemctl', 'is-active', service],
                capture_output=True,
                text=True,
                timeout=3
            )
            status['active'] = result.stdout.strip() == 'active'

            # Vérifier si le service est enabled
            result = subprocess.run(
                ['/usr/bin/systemctl', 'is-enabled', service],
                capture_output=True,
                text=True,
                timeout=3
            )
            status['enabled'] = result.stdout.strip() == 'enabled'

            # Récupérer les informations détaillées
            result = subprocess.run(
                ['/usr/bin/systemctl', 'status', service, '--no-pager', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                output = result.stdout
                # Chercher le PID
                pid_match = re.search(r'Main PID: (\d+)', output)
                if pid_match:
                    status['pid'] = int(pid_match.group(1))

                # Chercher la description
                desc_match = re.search(r'Description: (.+)', output)
                if desc_match:
                    status['description'] = desc_match.group(1).strip()

        except Exception as e:
            print(f"[!] Erreur status {service}: {e}")

        services_status[service] = status

    return services_status


# =================================================================================================
# Fonctions utilitaires
# =================================================================================================

def is_service_active(service_name):
    """Vérifie si un service systemd est actif avec vérification renforcée"""
    try:
        # Méthode 1: /usr/bin/systemctl is-active
        result = subprocess.run(
            ['/usr/bin/systemctl', 'is-active', service_name],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.stdout.strip() == 'active':
            return True

        # Méthode 2: Vérifier via les processus pour double confirmation
        if service_name == 'hostapd':
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] == 'hostapd':
                        return True
                    cmdline = proc.info.get('cmdline', [])
                    if cmdline and any('hostapd' in str(cmd) for cmd in cmdline):
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        elif service_name == 'dnsmasq':
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] == 'dnsmasq':
                        return True
                    cmdline = proc.info.get('cmdline', [])
                    if cmdline and any('dnsmasq' in str(cmd) for cmd in cmdline):
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        return False

    except Exception as e:
        print(f"[!] Erreur is_service_active {service_name}: {e}")
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
    """Retourne les informations des interfaces réseau - FONCTION CORRIGÉE"""
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
# Fonctions Ligolo (simplifiées pour l'exemple)
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
            ['sudo /usr/bin/lsof', '-i', '-n', '-P'],
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
            ['/usr/bin/lsof', '-i', '-n', '-P'],
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

# =================================================================================================
# Routes API
# =================================================================================================

@app.route('/api/status')
@login_required
def get_status():
    """Retourne le statut complet du système avec données WiFi AP corrigées"""
    try:
        ligolo_running, ligolo_pid = check_ligolo_agent_running()
        ligolo_conn_info = get_ligolo_connection_info()

        # Services avec statut réel
        services_detailed = get_real_service_status()
        services_status = {
            'ligolo-agent': services_detailed.get('ligolo-agent', {}).get('active', False),
            'hostapd': services_detailed.get('hostapd', {}).get('active', False),
            'dnsmasq': services_detailed.get('dnsmasq', {}).get('active', False),
            'ssh': services_detailed.get('ssh', {}).get('active', False),
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

        # Configuration AP dynamique
        ap_config = get_ap_config()
        ap_clients = get_ap_clients()
        ap_interface = get_ap_interface()

        return jsonify({
            'success': True,
            'services': services_status,
            'services_detailed': services_detailed,
            'system': system_info,
            'ligolo': ligolo_config,
            'routes': routes,
            'routes_count': len(routes),
            'ap': {
                'config': ap_config,
                'clients': ap_clients,
                'clients_count': len(ap_clients),
                'interface': ap_interface
            },
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


@app.route('/api/ap/status')
@login_required
def api_get_ap_status():
    """Statut complet de l'Access Point avec données dynamiques"""
    try:
        # Configuration dynamique
        config = get_ap_config()

        # Clients connectés
        clients = get_ap_clients()

        # Statut des services
        services = get_real_service_status()

        # Interface AP
        ap_interface = get_ap_interface()

        return jsonify({
            'success': True,
            'config': config,
            'clients': clients,
            'clients_count': len(clients),
            'services': {
                'hostapd': services.get('hostapd', {}),
                'dnsmasq': services.get('dnsmasq', {})
            },
            'interface': ap_interface,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        print(f"[!] Erreur api_get_ap_status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/ap/clients')
@login_required
def api_get_ap_clients():
    """Liste des clients connectés à l'AP avec données en temps réel"""
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
    """Configuration de l'AP lue depuis les fichiers système"""
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


@app.route('/api/routes')
@login_required
def get_routes_api():
    """Endpoint dédié aux routes"""
    try:
        routes = get_ligolo_routes()

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
                    ['/usr/bin/systemctl', 'start', service],
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
                    ['/usr/bin/systemctl', 'stop', service],
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
                    ['/usr/bin/systemctl', 'restart', service],
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


@app.route('/api/logs')
@login_required
def get_logs():
    """Retourne les logs système"""
    try:
        log_type = request.args.get('type', 'ligolo')
        lines = int(request.args.get('lines', 50))

        logs_data = {}

        if log_type in ['all', 'ligolo']:
            result = subprocess.run(
                ['/usr/bin/journalctl', '-u', 'ligolo-agent', '-n', str(lines), '--no-pager', '-o', 'short'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logs_data['ligolo'] = [
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


@app.route('/api/config/export')
@login_required
def export_config():
    """Exporte la configuration système"""
    try:
        config = {
            'ligolo': get_ligolo_config(),
            'ap': get_ap_config(),
            'network': get_network_interfaces(),
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
# Gestion des erreurs
# =================================================================================================

@app.errorhandler(404)
def not_found(error):
    if request.is_json:
        return jsonify({'success': False, 'error': 'Endpoint not found'}), 404
    return redirect(url_for('index'))


@app.errorhandler(500)
def internal_error(error):
    if request.is_json:
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    return redirect(url_for('index'))


# =================================================================================================
# Main
# =================================================================================================

def run_server(host='0.0.0.0', port=5000, debug=False):
    """Lance le serveur Flask"""
    print(f"[+] RaspPunzel Dashboard Backend v2.1 - COMPLET ET CORRIGÉ")
    print(f"[+] ===================================================")
    print(f"[+] Corrections apportées:")
    print(f"[+]   - Authentification complète")
    print(f"[+]   - Configuration WiFi AP dynamique")
    print(f"[+]   - Statut services en temps réel")
    print(f"[+]   - Détection clients connectés")
    print(f"[+]   - Interface AP automatique")
    print(f"[+]   - Toutes les erreurs de syntaxe corrigées")
    print(f"[+] ")
    load_auth_config()

    print(f"[+] Démarrage du serveur sur {host}:{port}")
    print(f"[+] Interface web: http://{host}:8080")
    print(f"[+] Utilisateur: {AUTH_CONFIG['username']}")
    print(f"[+] Mot de passe par défaut: rasppunzel")
    print(f"[+] ")

    try:
        socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du serveur...")
        sys.exit(0)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='RaspPunzel Dashboard Server - Version complète corrigée'
    )
    parser.add_argument('--host', default='0.0.0.0', help='Adresse d\'écoute')
    parser.add_argument('--port', type=int, default=5000, help='Port d\'écoute')
    parser.add_argument('--debug', action='store_true', help='Mode debug')

    args = parser.parse_args()
    run_server(args.host, args.port, args.debug)
