# RaspPunzel 🚀

**Implant RedTeam portable basé sur Raspberry Pi**

Un outil discret et autonome pour les tests d'intrusion, engagements RedTeam et évaluations de sécurité WiFi.

![RaspPunzel Banner](https://img.shields.io/badge/RaspPunzel-v1.0-green?style=for-the-badge) ![Platform](https://img.shields.io/badge/Platform-Raspberry_Pi-red?style=for-the-badge) ![OS](https://img.shields.io/badge/OS-Kali_Linux_ARM-blue?style=for-the-badge)

---

## 📋 Équipement Requis

| Composant | Spécification | Status |
|-----------|---------------|---------|
| **Raspberry Pi** | 4 (recommandé) ou 3B+ | ✅ Requis |
| **Carte SD** | 32GB minimum, Classe 10 | ✅ Requis |
| **Adaptateur WiFi** | USB compatible monitor mode | ✅ Requis |
| **Alimentation** | Power bank portable | 🔋 Recommandé |
| **Boîtier** | Discret pour déploiement | 📦 Optionnel |

### 📶 Adaptateurs WiFi Testés
- **Alfa AWUS036NEH** - Ralink RT3070 (2.4GHz)
- **Alfa AWUS036ACH** - Realtek RTL8812AU (2.4/5GHz)
- **TP-Link AC600** - Realtek RTL8811AU
- **Panda PAU09** - Ralink RT5372

---

## 🎯 Fonctionnalités Principales

### 🌐 **Accès Distant Multi-Interface**
- 📡 **Point d'accès WiFi caché** pour administration discrète
- 🔐 **SSH sécurisé** avec authentification par clé
- 💻 **Interface web moderne** avec contrôle en temps réel
- 🔄 **Auto-recovery** en cas de perte de connexion

### ⚔️ **Arsenal d'Outils Préinstallés**
- 🔍 **Reconnaissance avancée** (Nmap, Masscan, Kismet)
- 📶 **Attaques WiFi complètes** (Aircrack-ng, Wifite, Reaver)
- 🎯 **Exploitation ciblée** (Metasploit, Empire, Bettercap)
- 🔓 **Crackage de mots de passe** (John, Hashcat, Hydra)
- 🌐 **Sécurité web** (SQLMap, Nikto, Gobuster)

### 🏗️ **Infrastructure Robuste**
- 🚀 **Configuration automatique** au démarrage
- 📊 **Monitoring système** en temps réel
- 📝 **Logs détaillés** et rotation automatique
- 🔄 **Mises à jour automatisées** des outils

---

## ⚡ Installation Rapide

### 🔥 **Installation One-Shot**
```bash
# Cloner le repository
git clone https://github.com/theimposterz/rasppunzel.git
cd rasppunzel

# Installation automatisée (configuration interactive)
sudo ./install.sh

# Redémarrage pour finaliser
sudo reboot
```
---

## 🌐 Accès à l'Implant

### 📡 **Via Point d'Accès Caché (Méthode Principale)**
```
📶 SSID: MAINTENANCE_WIFI (réseau caché)
🔐 Mot de passe: SecureP@ss123!
🌐 IP Implant: 192.168.10.1
📍 Portée: ~50m (selon environnement)
```

### 🔌 **Via Réseau Local**
```bash
# Découvrir l'IP de RaspPunzel
nmap -sn 192.168.1.0/24 | grep -B2 "Raspberry Pi"

# Connexion directe
ssh admin@<ip-découverte>
```

### 💻 **Interfaces de Contrôle**

| Interface | URL/Commande | Description |
|-----------|-------------|-------------|
| 🌐 **Dashboard Web** | `http://192.168.10.1:8080` | Interface graphique complète |
| 💻 **SSH** | `ssh admin@192.168.10.1` | Ligne de commande sécurisée |
| 📱 **API REST** | `http://192.168.10.1:8080/api/` | Contrôle programmatique |

---

## 🛠️ Arsenal d'Outils Intégré

### 🔍 **Reconnaissance & Intelligence**
- **Nmap** - Scanner de ports et découverte réseau
- **Masscan** - Scanner haute performance
- **Kismet** - Détection WiFi passive
- **TheHarvester** - OSINT et reconnaissance
- **Recon-ng** - Framework de reconnaissance

### 📶 **Attaques WiFi Spécialisées**
- **Aircrack-ng Suite** - Outils WiFi complets
- **Wifite** - Attaques automatisées
- **Wifiphisher** - Rogue AP et phishing
- **Wifipumpkin3** - Framework d'attaque WiFi
- **EAPHammer** - Attaques EAP et WPA-Enterprise
- **Fluxion** - Attaques de déauthentification

### 🎯 **Exploitation & Post-Exploitation**
- **Metasploit Framework** - Exploitation modulaire
- **Empire** - Post-exploitation PowerShell
- **Social Engineer Toolkit** - Ingénierie sociale
- **BeEF** - Exploitation navigateur

### 🌐 **Sécurité Web & Applications**
- **SQLMap** - Injection SQL automatisée
- **Nikto** - Scanner vulnérabilités web
- **Gobuster** - Brute force répertoires/fichiers
- **OWASP ZAP** - Proxy de sécurité
- **XSStrike** - Détection XSS avancée

### 🔓 **Crackage & Brute Force**
- **John the Ripper** - Crackeur de hash universel
- **Hashcat** - Crackage GPU haute performance
- **Hydra** - Brute force réseau
- **Medusa** - Attaques par dictionnaire

### 🕵️ **Analyse & Forensique**
- **Wireshark** - Analyseur de protocoles
- **Binwalk** - Analyse de firmware
- **Foremost** - Récupération de fichiers
- **Volatility** - Analyse mémoire

---

## 📁 Architecture du Projet

```
rasppunzel/
├── 📄 README.md                    # Documentation principale
├── 🚀 install.sh                   # Installation automatisée
├── 📜 scripts/                     # Scripts de gestion
│   ├── setup-network.sh            # Configuration réseau
│   ├── install-tools.sh            # Installation des outils
│   ├── service-manager.sh          # Gestionnaire de services
│   ├── update-system.sh            # Mises à jour système
│   ├── start-services.sh           # Démarrage des services
│   └── stop-services.sh            # Arrêt des services
├── 🌐 web/                         # Interface web
│   └── dashboard.html              # Dashboard principal
├── ⚙️ config/                      # Fichiers de configuration
│   ├── network/                    # Configuration réseau
│   │   ├── hostapd.conf.template   # Point d'accès WiFi
│   │   ├── dnsmasq.conf.template   # Serveur DHCP/DNS
│   │   └── interfaces.template     # Interfaces réseau
│   ├── services/                   # Configuration des services
│   │   ├── nginx-rasppunzel.conf   # Serveur web
│   │   └── ssh-config.template     # Configuration SSH
│   └── systemd/                    # Services système
│       ├── rasppunzel-tower.service
│       └── rasppunzel-network.service
├── 📚 examples/                    # Guides et exemples
│   └── usage-guide.md             # Guide d'utilisation complet
├── 🔧 Makefile                     # Automatisation
├── 📄 LICENSE                      # Licence MIT
└── 🚫 .gitignore                   # Fichiers à ignorer
```

---

## 🎮 Guide d'Utilisation Rapide

### 🚀 **Déploiement sur Site**
1. **Préparation**: Charger la power bank, vérifier la carte SD
2. **Déploiement**: Placer discrètement le Pi dans la zone cible
3. **Activation**: Le Pi démarre automatiquement et active le point d'accès
4. **Connexion**: Se connecter au WiFi `MAINTENANCE_WIFI`
5. **Contrôle**: Accéder à `http://192.168.10.1:8080`

### 🔧 **Commandes de Base**

```bash
# 🚀 Gestion des services
make start          # Démarrer tous les services
make stop           # Arrêter tous les services  
make restart        # Redémarrer tous les services
make status         # Afficher l'état détaillé
make update         # Mettre à jour le système

# 🛠️ Scripts de gestion avancés
sudo ./scripts/service-manager.sh menu    # Menu interactif
sudo ./scripts/update-system.sh full      # Mise à jour complète
sudo ./scripts/setup-network.sh           # Reconfigurer le réseau

# 📊 Monitoring et logs
sudo journalctl -u rasppunzel-tower -f    # Logs en temps réel
sudo ./scripts/service-manager.sh logs    # Afficher les logs
sudo ./scripts/service-manager.sh check   # Test de connectivité
```

### 🎯 **Exemples d'Attaques**

```bash
# 🔍 Reconnaissance réseau
nmap -sn 192.168.10.0/24              # Découverte d'hôtes
nmap -sS -O 192.168.10.5              # Scan furtif avec OS detection

# 📶 Attaques WiFi automatisées
wifite --wpa --dict /usr/share/wordlists/rockyou.txt

# 🎯 Exploitation avec Metasploit
msfconsole -r /opt/rasppunzel-tools/scripts/auto_exploit.rc

# 🌐 Test de sécurité web
nikto -h http://192.168.10.5
sqlmap -u "http://192.168.10.5/login.php" --forms --batch
```

---

## 🔒 Sécurité & Configuration

### 🛡️ **Sécurisation Post-Installation**

```bash
# Changer les mots de passe par défaut
sudo passwd admin                    # Mot de passe utilisateur
sudo nano /etc/hostapd/hostapd.conf  # Mot de passe WiFi

# Générer des clés SSH
ssh-keygen -t ed25519 -C "rasppunzel@$(hostname)"
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys

# Désactiver l'authentification par mot de passe SSH
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### 🔐 **Configuration WiFi Avancée**

```bash
# Changer le canal WiFi (éviter les interférences)
sudo nano /etc/hostapd/hostapd.conf
# Modifier: channel=6 (1-11 pour 2.4GHz, 36-165 pour 5GHz)

# Ajuster la puissance de transmission
echo "iwconfig wlan1 txpower 15" >> /etc/rc.local

# Configuration 5GHz (si supporté)
hw_mode=a
channel=36
```

---

## 📊 Monitoring & Performance

### 📈 **Métriques Système**
- **CPU**: Raspberry Pi 4 (ARM Cortex-A72 1.5GHz)
- **RAM**: Utilisation optimisée (~500MB en fonctionnement)
- **Stockage**: ~8GB utilisés après installation complète
- **Réseau**: Point d'accès 150Mbps (802.11n)
- **Autonomie**: 6-8h avec power bank 10.000mAh

### 📊 **Dashboard Temps Réel**
L'interface web affiche :
- 🔋 État de la batterie et température CPU
- 📊 Utilisation RAM/CPU en temps réel
- 🌐 Clients connectés au point d'accès
- 📡 Qualité du signal WiFi
- 📝 Logs des outils en cours d'exécution

---

## 🚨 Scénarios d'Usage

### 🏢 **Test d'Intrusion Entreprise**
```bash
# 1. Déploiement discret dans les locaux
# 2. Connexion au réseau interne via Ethernet
# 3. Reconnaissance réseau automatisée...
```

### 🏠 **Audit Sécurité WiFi Résidentiel**
```bash
# 1. Scan des réseaux WiFi environnants
# 2. Test de sécurité WPS/WPA
# 3. Attaques de déauthentification
# 4. Analyse des mots de passe faibles
```

### 🎓 **Formation Cybersécurité**
```bash
# 1. Environnement d'apprentissage isolé
# 2. Exercices pratiques guidés
# 3. Simulation d'attaques réalistes
# 4. Laboratoire portable autonome
```

---

## 🔧 Dépannage

### ❗ **Problèmes Courants**

| Problème | Symptôme | Solution |
|----------|----------|----------|
| 📶 **WiFi non visible** | SSID absent des réseaux | `sudo systemctl restart hostapd` |
| 🌐 **Pas d'IP DHCP** | Connexion WiFi sans Internet | `sudo systemctl restart dnsmasq` |
| 💻 **Interface web inaccessible** | Erreur 502/503 | `sudo systemctl restart nginx` |
| 🔌 **Interface USB non détectée** | `wlan1` absent | Vérifier pilotes avec `dmesg` |

### 🛠️ **Commandes de Diagnostic**

```bash
# Test complet du système
sudo ./scripts/service-manager.sh check

# Vérification des interfaces réseau
ip addr show && iwconfig

# Test de connectivité
ping -c 4 8.8.8.8 && ping -c 4 192.168.10.1

# Logs détaillés
sudo journalctl -u rasppunzel-tower --since "1 hour ago"
```

---

## 🤝 Contribution

### 💡 **Contribuer au Projet**
```bash
# Fork du repository
git clone https://github.com/theimposterz/rasppunzel.git

# Créer une branche feature
git checkout -b feature/nouvelle-fonctionnalite

# Commiter les changements
git commit -m "feat: ajout nouvelle fonctionnalité"

# Push et Pull Request
git push origin feature/nouvelle-fonctionnalite
```

### 🐛 **Rapporter des Bugs**
- Utiliser les **Issues GitHub** 
- Inclure les **logs système** et **version du Pi**
- Préciser le **scénario de reproduction**

---

## 📜 Changelog

### 🆕 **v1.0.0** - Release Initiale
- ✅ Installation automatisée complète
- ✅ Interface web moderne avec thème Matrix
- ✅ 50+ outils de pentest préinstallés
- ✅ Point d'accès WiFi caché fonctionnel
- ✅ Scripts de gestion complets
- ✅ Documentation exhaustive

### 🔮 **Roadmap v1.1**
- 🔄 Support 4G/LTE pour accès distant
- 📱 Application mobile de contrôle
- 🤖 Automatisation IA pour reconnaissance
- 🔐 Certificats SSL auto-générés
- 📊 Dashboard analytics avancé

---

## ⚠️ Avertissement Légal

> **🚨 UTILISATION STRICTEMENT LÉGALE UNIQUEMENT**
> 
> RaspPunzel est un outil destiné **exclusivement** aux professionnels de la cybersécurité pour :
> - ✅ **Tests d'intrusion autorisés** avec contrat signé
> - ✅ **Formation et éducation** en cybersécurité  
> - ✅ **Recherche académique** et développement
> - ✅ **Audit de sécurité** de ses propres systèmes
>
> ❌ **INTERDIT POUR :**
> - Accès non autorisé à des systèmes tiers
> - Activités malveillantes ou criminelles
> - Violation de la vie privée
> - Toute utilisation illégale dans votre juridiction
>
> L'utilisateur assume **l'entière responsabilité** de l'usage conforme aux lois locales.

---

## 📞 Support & Communauté

### 🆘 **Obtenir de l'Aide**
- 📋 **Issues GitHub** : [github.com/theimposterz/rasppunzel/issues](https://github.com/theimposterz/rasppunzel/issues)
- 📖 **Wiki Documentation** : [github.com/theimposterz/rasppunzel/wiki](https://github.com/theimposterz/rasppunzel/wiki)
- 💬 **Discussions** : [github.com/theimposterz/rasppunzel/discussions](https://github.com/theimposterz/rasppunzel/discussions)

### 🌟 **Remerciements**
- **Offensive Security** pour Kali Linux
- **Raspberry Pi Foundation** 
- **Communauté cybersécurité** open source
- **Contributeurs** et testeurs du projet

---

<div align="center">

**⭐ Si RaspPunzel vous a été utile, n'hésitez pas à mettre une étoile sur GitHub ! ⭐**

[![GitHub stars](https://img.shields.io/github/stars/theimposterz/rasppunzel?style=social)](https://github.com/theimposterz/rasppunzel/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/theimposterz/rasppunzel?style=social)](https://github.com/theimposterz/rasppunzel/network)

---

**Made with ❤️ for the cybersecurity community**

`RaspPunzel v1.0 - "Libère tes cheveux... WiFi !"`

</div>