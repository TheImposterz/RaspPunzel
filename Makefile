# RaspPunzel Makefile avec Dashboard Web
.PHONY: help install install-web start stop restart status clean web-dev web-logs

# Variables
INSTALL_DIR = /opt/rasppunzel
WEB_SERVICE = rasppunzel-web
PYTHON_ENV = $(INSTALL_DIR)/web/venv

# Colors
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

help: ## Afficher cette aide
	@echo "$(GREEN)RaspPunzel - Makefile Commands$(NC)"
	@echo ""
	@echo "$(YELLOW)Installation:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' | \
		grep -E "(install|setup)"
	@echo ""
	@echo "$(YELLOW)Services:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' | \
		grep -E "(start|stop|restart|status)"
	@echo ""
	@echo "$(YELLOW)Dashboard Web:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' | \
		grep -E "(web|dashboard)"
	@echo ""
	@echo "$(YELLOW)Maintenance:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' | \
		grep -E "(clean|update|backup)"

install: ## Installation complète du système RaspPunzel
	@echo "$(GREEN)[+] Installation RaspPunzel...$(NC)"
	@sudo bash install.sh
	@echo "$(GREEN)[+] Installation terminée$(NC)"

install-web: ## Installation du dashboard web uniquement
	@echo "$(GREEN)[+] Installation du dashboard web RaspPunzel...$(NC)"
	
	# Création des répertoires
	@sudo mkdir -p $(INSTALL_DIR)/web/api
	@sudo mkdir -p $(INSTALL_DIR)/web/assets
	@sudo mkdir -p /var/log/rasppunzel
	
	# Installation Python et dépendances
	@echo "$(YELLOW)[~] Installation des dépendances Python...$(NC)"
	@sudo apt-get update -qq
	@sudo apt-get install -y python3 python3-pip python3-venv
	
	# Environnement virtuel
	@echo "$(YELLOW)[~] Configuration de l'environnement virtuel...$(NC)"
	@sudo python3 -m venv $(PYTHON_ENV)
	@sudo $(PYTHON_ENV)/bin/pip install --upgrade pip
	@sudo $(PYTHON_ENV)/bin/pip install -r web/api/requirements.txt
	
	# Copie des fichiers
	@echo "$(YELLOW)[~] Installation des fichiers web...$(NC)"
	@sudo cp web/api/app.py $(INSTALL_DIR)/web/api/
	@sudo cp web/dashboard.html $(INSTALL_DIR)/web/
	@sudo cp -r web/assets/* $(INSTALL_DIR)/web/assets/ 2>/dev/null || true
	
	# Configuration du service
	@echo "$(YELLOW)[~] Configuration du service systemd...$(NC)"
	@sudo cp config/systemd/rasppunzel-web.service /etc/systemd/system/ 2>/dev/null || \
		sudo tee /etc/systemd/system/rasppunzel-web.service > /dev/null <<EOF
[Unit]
Description=RaspPunzel Web Dashboard
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=$(INSTALL_DIR)/web
Environment=PATH=$(PYTHON_ENV)/bin
ExecStart=$(PYTHON_ENV)/bin/python api/app.py --host=0.0.0.0 --port=8080
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rasppunzel-web

[Install]
WantedBy=multi-user.target
EOF
	
	# Permissions et activation
	@sudo chown -R pi:pi $(INSTALL_DIR)/web
	@sudo systemctl daemon-reload
	@sudo systemctl enable rasppunzel-web
	
	@echo "$(GREEN)[+] Dashboard web installé avec succès$(NC)"
	@echo "$(YELLOW)[i] Utilisez 'make start-web' pour démarrer$(NC)"

setup-network: ## Configuration du réseau
	@echo "$(GREEN)[+] Configuration du réseau...$(NC)"
	@sudo bash scripts/setup-network.sh

setup-tools: ## Installation des outils de sécurité
	@echo "$(GREEN)[+] Installation des outils de sécurité...$(NC)"
	@sudo bash scripts/setup-tools.sh

start: ## Démarrer tous les services RaspPunzel
	@echo "$(GREEN)[+] Démarrage des services RaspPunzel...$(NC)"
	@sudo bash scripts/start-services.sh
	@sudo systemctl start rasppunzel-network rasppunzel-tower
	@make start-web

start-web: ## Démarrer le dashboard web uniquement
	@echo "$(GREEN)[+] Démarrage du dashboard web...$(NC)"
	@sudo systemctl start $(WEB_SERVICE)
	@sleep 2
	@if systemctl is-active --quiet $(WEB_SERVICE); then \
		echo "$(GREEN)[✓] Dashboard web démarré$(NC)"; \
		echo "$(YELLOW)[i] Accessible sur http://$(shell hostname -I | awk '{print $$1}'):8080$(NC)"; \
	else \
		echo "$(RED)[✗] Échec du démarrage du dashboard web$(NC)"; \
		systemctl status $(WEB_SERVICE) --no-pager; \
	fi

stop: ## Arrêter tous les services RaspPunzel
	@echo "$(YELLOW)[~] Arrêt des services RaspPunzel...$(NC)"
	@sudo systemctl stop rasppunzel-network rasppunzel-tower $(WEB_SERVICE) 2>/dev/null || true
	@sudo bash scripts/stop-services.sh
	@echo "$(GREEN)[+] Services arrêtés$(NC)"

stop-web: ## Arrêter le dashboard web uniquement
	@echo "$(YELLOW)[~] Arrêt du dashboard web...$(NC)"
	@sudo systemctl stop $(WEB_SERVICE)
	@sudo pkill -f "rasppunzel.*app.py" 2>/dev/null || true
	@echo "$(GREEN)[+] Dashboard web arrêté$(NC)"

restart: ## Redémarrer tous les services
	@echo "$(YELLOW)[~] Redémarrage des services RaspPunzel...$(NC)"
	@make stop
	@sleep 2
	@make start

restart-web: ## Redémarrer le dashboard web uniquement
	@echo "$(YELLOW)[~] Redémarrage du dashboard web...$(NC)"
	@make stop-web
	@sleep 2
	@make start-web

status: ## Afficher le statut des services
	@echo "$(GREEN)═══════════════════════════════════════$(NC)"
	@echo "$(GREEN)       STATUT SERVICES RASPPUNZEL$(NC)"
	@echo "$(GREEN)═══════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)Services système:$(NC)"
	@for service in hostapd dnsmasq ssh rasppunzel-network rasppunzel-tower $(WEB_SERVICE); do \
		if systemctl is-active --quiet $service 2>/dev/null; then \
			echo "  $(GREEN)✓$(NC) $service: $(GREEN)ACTIF$(NC)"; \
		else \
			echo "  $(RED)✗$(NC) $service: $(RED)INACTIF$(NC)"; \
		fi \
	done
	@echo ""
	@echo "$(YELLOW)Réseau:$(NC)"
	@ip -4 addr show | grep -E "inet.*scope global" | awk '{print "  📡 " $NF " : " $2}' | sed 's|/.*||' || echo "  $(RED)Aucune interface active$(NC)"
	@echo ""
	@if systemctl is-active --quiet $(WEB_SERVICE); then \
		echo "$(YELLOW)Dashboard web:$(NC)"; \
		echo "  $(GREEN)🌐 http://$(shell hostname -I | awk '{print $1}'):8080$(NC)"; \
		echo "  $(GREEN)📶 http://10.0.0.1:8080 (via AP)$(NC)"; \
	else \
		echo "$(YELLOW)Dashboard web:$(NC) $(RED)INACCESSIBLE$(NC)"; \
	fi

web-dev: ## Lancer le serveur web en mode développement
	@echo "$(GREEN)[+] Mode développement - Dashboard web$(NC)"
	@cd web && python3 api/app.py --debug --port=5000

web-logs: ## Voir les logs du dashboard web
	@echo "$(GREEN)[+] Logs du dashboard web (Ctrl+C pour quitter):$(NC)"
	@sudo journalctl -u $(WEB_SERVICE) -f

web-shell: ## Accéder au shell Python du dashboard
	@echo "$(GREEN)[+] Shell interactif Python$(NC)"
	@cd web/api && $(PYTHON_ENV)/bin/python -i -c "from app import *; print('Dashboard API chargé')"

dashboard-install: install-web ## Alias pour install-web

dashboard-start: start-web ## Alias pour start-web

dashboard-stop: stop-web ## Alias pour stop-web

dashboard-logs: web-logs ## Alias pour web-logs

update: ## Mettre à jour le système et les outils
	@echo "$(GREEN)[+] Mise à jour du système RaspPunzel...$(NC)"
	@sudo bash scripts/update-system.sh
	@echo "$(GREEN)[+] Mise à jour terminée$(NC)"

update-web: ## Mettre à jour uniquement le dashboard web
	@echo "$(GREEN)[+] Mise à jour du dashboard web...$(NC)"
	@make stop-web
	@sudo $(PYTHON_ENV)/bin/pip install --upgrade -r web/api/requirements.txt
	@sudo cp web/api/app.py $(INSTALL_DIR)/web/api/
	@sudo cp web/dashboard.html $(INSTALL_DIR)/web/
	@sudo chown -R pi:pi $(INSTALL_DIR)/web
	@make start-web
	@echo "$(GREEN)[+] Dashboard web mis à jour$(NC)"

backup: ## Sauvegarder la configuration
	@echo "$(GREEN)[+] Sauvegarde de la configuration RaspPunzel...$(NC)"
	@sudo mkdir -p /root/rasppunzel-backup/$(shell date +%Y%m%d-%H%M%S)
	@sudo cp -r config /root/rasppunzel-backup/$(shell date +%Y%m%d-%H%M%S)/
	@sudo cp -r $(INSTALL_DIR)/web /root/rasppunzel-backup/$(shell date +%Y%m%d-%H%M%S)/ 2>/dev/null || true
	@echo "$(GREEN)[+] Sauvegarde créée dans /root/rasppunzel-backup/$(NC)"

clean: ## Nettoyer les fichiers temporaires et logs
	@echo "$(YELLOW)[~] Nettoyage des fichiers temporaires...$(NC)"
	@sudo journalctl --vacuum-time=7d
	@sudo rm -rf /tmp/rasppunzel-*
	@sudo find /var/log -name "*.log" -size +100M -delete 2>/dev/null || true
	@sudo apt-get autoremove -y
	@sudo apt-get autoclean
	@echo "$(GREEN)[+] Nettoyage terminé$(NC)"

uninstall: ## Désinstaller RaspPunzel (ATTENTION: supprime tout)
	@echo "$(RED)[!] ATTENTION: Cette action va supprimer RaspPunzel$(NC)"
	@read -p "Êtes-vous sûr ? (oui/non): " confirm && [ "$confirm" = "oui" ]
	@echo "$(YELLOW)[~] Arrêt des services...$(NC)"
	@make stop
	@echo "$(YELLOW)[~] Suppression des services systemd...$(NC)"
	@sudo systemctl disable rasppunzel-network rasppunzel-tower $(WEB_SERVICE) 2>/dev/null || true
	@sudo rm -f /etc/systemd/system/rasppunzel-*.service
	@sudo systemctl daemon-reload
	@echo "$(YELLOW)[~] Suppression des fichiers...$(NC)"
	@sudo rm -rf $(INSTALL_DIR)
	@sudo rm -rf /var/log/rasppunzel
	@echo "$(GREEN)[+] RaspPunzel désinstallé$(NC)"

check: ## Vérifier les prérequis et dépendances
	@echo "$(GREEN)[+] Vérification des prérequis RaspPunzel$(NC)"
	@echo ""
	@echo "$(YELLOW)Système:$(NC)"
	@echo "  OS: $(shell cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
	@echo "  Kernel: $(shell uname -r)"
	@echo "  Architecture: $(shell uname -m)"
	@echo ""
	@echo "$(YELLOW)Outils requis:$(NC)"
	@for tool in python3 systemctl hostapd dnsmasq; do \
		if command -v $tool >/dev/null 2>&1; then \
			echo "  $(GREEN)✓$(NC) $tool"; \
		else \
			echo "  $(RED)✗$(NC) $tool $(RED)(manquant)$(NC)"; \
		fi \
	done
	@echo ""
	@echo "$(YELLOW)Outils de sécurité:$(NC)"
	@for tool in nmap masscan aircrack-ng wifite reaver nikto gobuster hydra john hashcat; do \
		if command -v $tool >/dev/null 2>&1; then \
			echo "  $(GREEN)✓$(NC) $tool"; \
		else \
			echo "  $(YELLOW)○$(NC) $tool $(YELLOW)(optionnel)$(NC)"; \
		fi \
	done
	@echo ""
	@if [ -d "$(PYTHON_ENV)" ]; then \
		echo "$(YELLOW)Environnement Python:$(NC)"; \
		echo "  $(GREEN)✓$(NC) Environnement virtuel: $(PYTHON_ENV)"; \
		echo "  Python: $(shell $(PYTHON_ENV)/bin/python --version 2>/dev/null || echo 'N/A')"; \
	else \
		echo "$(YELLOW)Environnement Python:$(NC) $(RED)Non installé$(NC)"; \
	fi

logs: ## Voir les logs de tous les services
	@echo "$(GREEN)[+] Logs des services RaspPunzel (Ctrl+C pour quitter):$(NC)"
	@sudo journalctl -u hostapd -u dnsmasq -u rasppunzel-network -u rasppunzel-tower -u $(WEB_SERVICE) -f

info: ## Afficher les informations système détaillées
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)                    INFORMATIONS RASPPUNZEL$(NC)"
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)📁 Structure du projet:$(NC)"
	@find . -maxdepth 2 -type d | sort | sed 's|^\./|  |' | head -15
	@echo ""
	@echo "$(YELLOW)🔧 Scripts disponibles:$(NC)"
	@ls scripts/*.sh 2>/dev/null | sed 's|scripts/|  |' || echo "  Aucun script trouvé"
	@echo ""
	@echo "$(YELLOW)⚙️  Fichiers de configuration:$(NC)"
	@find config -name "*.conf" -o -name "*.template" -o -name "*.service" 2>/dev/null | sed 's|^|  |' || echo "  Aucune configuration trouvée"
	@echo ""
	@echo "$(YELLOW)🌐 Dashboard web:$(NC)"
	@if [ -f "web/api/app.py" ]; then \
		echo "  ✓ Backend API: web/api/app.py"; \
	else \
		echo "  ✗ Backend API: manquant"; \
	fi
	@if [ -f "web/dashboard.html" ]; then \
		echo "  ✓ Frontend: web/dashboard.html"; \
	else \
		echo "  ✗ Frontend: manquant"; \
	fi
	@echo ""
	@if systemctl is-active --quiet $(WEB_SERVICE); then \
		echo "$(YELLOW)🔗 Accès web:$(NC)"; \
		echo "  http://$(shell hostname -I | awk '{print $1}'):8080"; \
		echo "  http://10.0.0.1:8080 (via point d'accès)"; \
	fi

# Targets de développement
dev-setup: ## Configuration de l'environnement de développement
	@echo "$(GREEN)[+] Configuration environnement de développement$(NC)"
	@python3 -m venv venv-dev
	@./venv-dev/bin/pip install --upgrade pip
	@./venv-dev/bin/pip install -r web/api/requirements.txt
	@./venv-dev/bin/pip install black flake8 pytest
	@echo "$(GREEN)[+] Environnement de développement prêt$(NC)"
	@echo "$(YELLOW)[i] Activez avec: source venv-dev/bin/activate$(NC)"

test: ## Lancer les tests (si disponibles)
	@echo "$(GREEN)[+] Lancement des tests...$(NC)"
	@if [ -d "tests" ]; then \
		python -m pytest tests/ -v; \
	else \
		echo "$(YELLOW)[i] Aucun test configuré$(NC)"; \
	fi

# Targets de debugging
debug-network: ## Débugger la configuration réseau
	@echo "$(GREEN)[+] Debug configuration réseau$(NC)"
	@echo ""
	@echo "$(YELLOW)Interfaces réseau:$(NC)"
	@ip addr show
	@echo ""
	@echo "$(YELLOW)Routes:$(NC)"
	@ip route show
	@echo ""
	@echo "$(YELLOW)Processus réseau:$(NC)"
	@sudo netstat -tulpn | grep -E "(hostapd|dnsmasq|:8080)"

debug-services: ## Débugger les services systemd
	@echo "$(GREEN)[+] Debug services systemd$(NC)"
	@for service in hostapd dnsmasq rasppunzel-network rasppunzel-tower $(WEB_SERVICE); do \
		echo ""; \
		echo "$(YELLOW)═══ $service ═══$(NC)"; \
		sudo systemctl status $service --no-pager || true; \
	done

# Raccourcis utiles
install-all: install install-web ## Installation complète avec dashboard web

start-all: start ## Alias pour start

stop-all: stop ## Alias pour stop

# Validation du Makefile
.PHONY: validate
validate: ## Valider la syntaxe du Makefile
	@echo "$(GREEN)[+] Validation du Makefile...$(NC)"
	@make -n help >/dev/null && echo "$(GREEN)[✓] Makefile valide$(NC)" || echo "$(RED)[✗] Erreur dans le Makefile$(NC)"