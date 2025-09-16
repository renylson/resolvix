#!/bin/bash

#######################################################
# Resolvix 
# Autor: Renylson Marques <renylsonm@gmail.com>
# GitHub: https://github.com/renylson/resolvix
# Versão: 2.0.0
#######################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/resolvix"
DASHBOARD_DIR="$INSTALL_DIR/dashboard"
VERSION="2.0.0"

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "██████╗ ███████╗███████╗ ██████╗ ██╗    ██╗   ██╗██╗██╗  ██╗"
    echo "██╔══██╗██╔════╝██╔════╝██╔═══██╗██║    ██║   ██║██║╚██╗██╔╝"
    echo "██████╔╝█████╗  ███████╗██║   ██║██║    ██║   ██║██║ ╚███╔╝ "
    echo "██╔══██╗██╔══╝  ╚════██║██║   ██║██║    ╚██╗ ██╔╝██║ ██╔██╗ "
    echo "██║  ██║███████╗███████║╚██████╔╝███████╗╚████╔╝ ██║██╔╝ ██╗"
    echo "╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝ ╚═══╝  ╚═╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${GREEN}Sistema Unificado de DNS Management v$VERSION${NC}"
    echo -e "${YELLOW}Autor: Renylson Marques <renylsonm@gmail.com>${NC}"
    echo ""
}

log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERRO] $1${NC}"; }
warning() { echo -e "${YELLOW}[AVISO] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }
success() { echo -e "${GREEN}[SUCESSO] $1${NC}"; }

show_help() {
    echo -e "${WHITE}RESOLVIX - Sistema Unificado de DNS Management${NC}"
    echo ""
    echo -e "${CYAN}USO:${NC} $0 [COMANDO] [OPÇÕES]"
    echo ""
    echo -e "${CYAN}COMANDOS:${NC}"
    echo -e "${YELLOW}  install${NC}         Instalar sistema completo"
    echo -e "${YELLOW}  uninstall${NC}       Remover sistema"
    echo -e "${YELLOW}  status${NC}          Verificar status"
    echo -e "${YELLOW}  start${NC}           Iniciar serviços"
    echo -e "${YELLOW}  stop${NC}            Parar serviços"
    echo -e "${YELLOW}  restart${NC}         Reiniciar serviços"
    echo -e "${YELLOW}  test${NC}            Testar DNS"
    echo -e "${YELLOW}  logs${NC}            Ver logs"
    echo -e "${YELLOW}  dashboard${NC}       Gerenciar dashboard"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Execute como root (use sudo)"
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

create_resolvix_user() {
    local username="resolvix"
    
    if id "$username" &>/dev/null; then
        return 0
    fi
    
    info "Criando usuário resolvix..."
    useradd -r -s /bin/false -c "ResolvIX System User" -d /var/lib/resolvix "$username"
    usermod -a -G bind "$username"
    
    mkdir -p /var/lib/resolvix /var/log/resolvix /var/backups/resolvix
    chown "$username:$username" /var/lib/resolvix
    chown -R "$username:bind" /var/log/resolvix /var/backups/resolvix
    chmod 750 /var/lib/resolvix
    chmod -R 775 /var/log/resolvix /var/backups/resolvix
}

install_dependencies() {
    local distro=$(detect_distro)
    
    info "Instalando dependências..."
    
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        error "Sem conectividade com a internet"
        exit 1
    fi
    
    case $distro in
        ubuntu|debian)
            apt-get update
            apt-get install -y bind9 bind9-utils python3 python3-pip python3-venv curl bind9-dnsutils bc lsof
            ;;
        centos|rhel|fedora)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y bind bind-utils python3 python3-pip curl bc lsof
            else
                yum install -y bind bind-utils python3 python3-pip curl bc lsof
            fi
            ;;
        *)
            error "Distribuição não suportada: $distro"
            exit 1
            ;;
    esac
}

generate_bind_config() {
    info "Configurando BIND9..."
    
    [[ -f "/etc/bind/named.conf" ]] && cp "/etc/bind/named.conf" "/etc/bind/named.conf.backup.$(date +%Y%m%d_%H%M%S)"
    
    cat > /etc/bind/named.conf << 'EOF'
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/acl.conf";
EOF

    cat > /etc/bind/named.conf.options << 'EOF'
options {
    directory "/var/cache/bind";
    listen-on port 53 { any; };
    listen-on-v6 port 53 { any; };
    
    recursive-clients 10000;
    tcp-clients 1000;
    clients-per-query 100;
    max-clients-per-query 200;
    
    max-cache-size 512M;
    max-cache-ttl 86400;
    max-ncache-ttl 3600;
    
    edns-udp-size 4096;
    max-udp-size 4096;
    
    forwarders {
        8.8.8.8;
        8.8.4.4;
        1.1.1.1;
        1.0.0.1;
    };
    
    recursion yes;
    allow-recursion { any; };
    allow-query { any; };
    allow-transfer { none; };
    
    tcp-listen-queue 100;
    dnssec-validation auto;
    version "Resolvix DNS Server";
    
    statistics-file "/var/cache/bind/named.stats";
    zone-statistics yes;
};

statistics-channels {
    inet 127.0.0.1 port 8053;
};

logging {
    channel bind_log {
        file "/var/log/named/bind.log" versions 3 size 5m;
        severity info;
        print-category yes;
        print-severity yes;
        print-time yes;
    };
    
    category default { bind_log; };
    category queries { bind_log; };
    category security { bind_log; };
};
EOF

    cat > /etc/bind/named.conf.local << 'EOF'
zone "localhost" {
    type master;
    file "/etc/bind/db.local";
};

zone "127.in-addr.arpa" {
    type master;
    file "/etc/bind/db.127";
};

zone "0.in-addr.arpa" {
    type master;
    file "/etc/bind/db.0";
};

zone "255.in-addr.arpa" {
    type master;
    file "/etc/bind/db.255";
};
EOF

    cat > /etc/bind/acl.conf << 'EOF'
acl "trusted" {
    127.0.0.0/8;
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
};

acl "blackhole" {
    none;
};
EOF

    mkdir -p /var/log/named
    chown bind:bind /var/log/named
    
    if ! named-checkconf; then
        error "Erro na configuração do BIND9"
        exit 1
    fi
}

setup_dashboard() {
    info "Configurando dashboard..."
    
    mkdir -p "$INSTALL_DIR"
    
    if [[ -d "$SCRIPT_DIR/dashboard" ]]; then
        cp -r "$SCRIPT_DIR/dashboard" "$INSTALL_DIR/"
        cp "$SCRIPT_DIR"/*.sh "$INSTALL_DIR/" 2>/dev/null || true
        cp "$SCRIPT_DIR"/*.md "$INSTALL_DIR/" 2>/dev/null || true
        cp "$SCRIPT_DIR/LICENSE" "$INSTALL_DIR/" 2>/dev/null || true
        chown -R resolvix:bind "$INSTALL_DIR"
        chmod -R 755 "$INSTALL_DIR"
    else
        error "Diretório dashboard não encontrado"
        return 1
    fi
    
    cd "$DASHBOARD_DIR"
    
    if [[ ! -f "requirements.txt" ]]; then
        cat > requirements.txt << 'EOF'
Flask==2.3.3
Flask-Login==0.6.3
Flask-WTF==1.1.1
Werkzeug==2.3.7
bcrypt==4.0.1
psutil==5.9.5
requests==2.31.0
python-dotenv==1.0.0
EOF
    fi
    
    [[ ! -d "venv" ]] && python3 -m venv venv
    
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    setup_admin_credentials
    chown -R resolvix:bind "$INSTALL_DIR"
    cd "$SCRIPT_DIR"
}

setup_admin_credentials() {
    info "Configurando credenciais do administrador..."
    
    if [[ -f "$DASHBOARD_DIR/data/credentials.json" ]]; then
        warning "Credenciais já configuradas"
        read -p "Reconfigurar? (y/N): " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && return 0
    fi
    
    echo ""
    echo -e "${CYAN}=== Configuração do Administrador ===${NC}"
    
    while true; do
        read -p "Nome de usuário [admin]: " admin_username
        admin_username=${admin_username:-admin}
        [[ "$admin_username" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]] && break
        echo -e "${RED}Nome inválido (apenas letras, números, _ ou -)${NC}"
    done
    
    while true; do
        echo ""
        echo -e "${YELLOW}Senha deve ter 8+ caracteres com maiúscula, minúscula, número e símbolo${NC}"
        read -s -p "Senha: " admin_password
        echo ""
        read -s -p "Confirme: " admin_password_confirm
        echo ""
        
        [[ "$admin_password" != "$admin_password_confirm" ]] && { echo -e "${RED}Senhas não coincidem${NC}"; continue; }
        [[ ${#admin_password} -lt 8 ]] && { echo -e "${RED}Muito curta${NC}"; continue; }
        [[ ! "$admin_password" =~ [A-Z] ]] && { echo -e "${RED}Falta maiúscula${NC}"; continue; }
        [[ ! "$admin_password" =~ [a-z] ]] && { echo -e "${RED}Falta minúscula${NC}"; continue; }
        [[ ! "$admin_password" =~ [0-9] ]] && { echo -e "${RED}Falta número${NC}"; continue; }
        [[ ! "$admin_password" =~ [^a-zA-Z0-9] ]] && { echo -e "${RED}Falta símbolo${NC}"; continue; }
        break
    done
    
    mkdir -p "$DASHBOARD_DIR/data"
    chmod 700 "$DASHBOARD_DIR/data"
    
    cd "$DASHBOARD_DIR"
    source venv/bin/activate
    
    python3 -c "
import sys
sys.path.append('.')
from auth import auth_manager

success, message = auth_manager.create_admin_user('$admin_username', '$admin_password')
if success:
    print('SUCCESS: ' + message)
else:
    print('ERROR: ' + message)
    sys.exit(1)
" && success "Usuário criado: $admin_username" || { error "Falha ao criar usuário"; return 1; }
    
    cd "$SCRIPT_DIR"
}

setup_dashboard_service() {
    info "Configurando serviço systemd..."
    
    chown -R resolvix:bind "$DASHBOARD_DIR"
    chmod -R 755 "$DASHBOARD_DIR"
    chown :bind /etc/bind/acl.conf
    chmod 664 /etc/bind/acl.conf
    
    cat > /etc/systemd/system/resolvix-dashboard.service << EOF
[Unit]
Description=Resolvix DNS Dashboard
After=network.target bind9.service
Requires=bind9.service

[Service]
Type=simple
User=resolvix
Group=bind
WorkingDirectory=$DASHBOARD_DIR
Environment=PATH=$DASHBOARD_DIR/venv/bin
ExecStart=$DASHBOARD_DIR/venv/bin/python $DASHBOARD_DIR/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SupplementaryGroups=bind

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable resolvix-dashboard
}

create_global_command() {
    cp "$SCRIPT_DIR/resolvix.sh" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/resolvix.sh"
    chown resolvix:bind "$INSTALL_DIR/resolvix.sh"
    ln -sf "$INSTALL_DIR/resolvix.sh" /usr/local/bin/resolvix
    success "Comando 'resolvix' disponível globalmente"
}

install_system() {
    show_banner
    log "Iniciando instalação do Resolvix DNS Server..."
    check_root
    
    if systemctl is-active --quiet named && systemctl is-active --quiet resolvix-dashboard; then
        warning "Sistema já instalado"
        read -p "Reinstalar? (y/N): " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    fi
    
    install_dependencies
    create_resolvix_user
    generate_bind_config
    
    systemctl enable named 2>/dev/null || true
    systemctl restart named || { error "Falha ao iniciar BIND9"; exit 1; }
    
    setup_dashboard || { error "Falha ao configurar dashboard"; exit 1; }
    setup_dashboard_service
    create_global_command
    
    systemctl start resolvix-dashboard || { warning "Falha ao iniciar dashboard"; sleep 3; systemctl start resolvix-dashboard || true; }
    
    sleep 5
    if systemctl is-active --quiet named && systemctl is-active --quiet resolvix-dashboard; then
        success "Instalação concluída!"
        echo ""
        info "Serviços:"
        echo "  - DNS Server: porta 53"
        echo "  - Statistics: http://127.0.0.1:8053"
        echo "  - Dashboard: http://127.0.0.1:5000"
    else
        error "Falha na instalação"
        exit 1
    fi
}

check_status() {
    show_banner
    info "Status do Resolvix DNS Server..."
    echo ""
    
    systemctl is-active --quiet named && echo -e "${GREEN}✓ BIND9 rodando${NC}" || echo -e "${RED}✗ BIND9 parado${NC}"
    systemctl is-active --quiet resolvix-dashboard && echo -e "${GREEN}✓ Dashboard rodando${NC}" || echo -e "${RED}✗ Dashboard parado${NC}"
    named-checkconf 2>/dev/null && echo -e "${GREEN}✓ Configuração válida${NC}" || echo -e "${RED}✗ Configuração inválida${NC}"
    timeout 5 dig @127.0.0.1 google.com A +short > /dev/null 2>&1 && echo -e "${GREEN}✓ DNS funcionando${NC}" || echo -e "${RED}✗ DNS falhando${NC}"
}

test_dns() {
    info "Testando resolução DNS..."
    echo ""
    
    local domains=("google.com" "github.com" "cloudflare.com")
    local types=("A" "AAAA" "MX")
    
    for domain in "${domains[@]}"; do
        echo -e "${CYAN}Testando: $domain${NC}"
        for type in "${types[@]}"; do
            local start_time=$(date +%s.%N)
            local result=$(dig @127.0.0.1 "$domain" "$type" +short +time=5 2>/dev/null | head -1)
            local end_time=$(date +%s.%N)
            local duration=$(echo "($end_time - $start_time) * 1000" | bc | cut -d. -f1)
            
            if [[ -n "$result" ]]; then
                echo -e "  ${GREEN}✓ $type: $result (${duration}ms)${NC}"
            else
                echo -e "  ${RED}✗ $type: Falhou${NC}"
            fi
        done
        echo ""
    done
}

manage_dashboard() {
    local action="$1"
    check_root
    
    case "$action" in
        "start") systemctl start resolvix-dashboard; success "Dashboard iniciado" ;;
        "stop") systemctl stop resolvix-dashboard; success "Dashboard parado" ;;
        "restart") systemctl restart resolvix-dashboard; success "Dashboard reiniciado" ;;
        "status") 
            if systemctl is-active --quiet resolvix-dashboard; then
                success "Dashboard rodando - http://127.0.0.1:5000"
            else
                warning "Dashboard parado"
            fi ;;
        "logs") journalctl -u resolvix-dashboard -f ;;
        *) 
            echo -e "${YELLOW}Opções: start|stop|restart|status|logs${NC}" ;;
    esac
}

uninstall_system() {
    warning "Isso removerá o Resolvix DNS Server completamente"
    read -p "Continuar? (y/N): " -r
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    
    check_root
    info "Removendo Resolvix..."
    
    systemctl stop resolvix-dashboard named 2>/dev/null || true
    systemctl disable resolvix-dashboard named 2>/dev/null || true
    
    pkill -f "python.*app.py" 2>/dev/null || true
    pkill -f "named" 2>/dev/null || true
    
    rm -f /etc/systemd/system/resolvix-dashboard.service
    systemctl daemon-reload
    
    local backup_dir="/root/resolvix-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    [[ -f /etc/bind/named.conf ]] && cp -r /etc/bind/* "$backup_dir/" 2>/dev/null
    
    rm -rf /etc/bind /var/cache/bind /var/log/bind "$INSTALL_DIR"
    
    if id "resolvix" &>/dev/null; then
        userdel resolvix 2>/dev/null || true
        rm -rf /var/lib/resolvix 2>/dev/null || true
    fi
    
    rm -f /usr/local/bin/resolvix
    
    success "Resolvix removido - Backup em: $backup_dir"
}

main() {
    local command="$1"
    shift 2>/dev/null || true
    
    case "$command" in
        "install") install_system ;;
        "uninstall") uninstall_system ;;
        "status") check_status ;;
        "start") check_root; systemctl start named resolvix-dashboard; success "Serviços iniciados" ;;
        "stop") check_root; systemctl stop named resolvix-dashboard; success "Serviços parados" ;;
        "restart") check_root; systemctl restart named resolvix-dashboard; success "Serviços reiniciados" ;;
        "test") test_dns ;;
        "logs") 
            echo -e "${CYAN}Logs do BIND9:${NC}"
            journalctl -u named -n 10 --no-pager
            echo -e "${CYAN}Logs do Dashboard:${NC}"
            journalctl -u resolvix-dashboard -n 10 --no-pager ;;
        "dashboard") manage_dashboard "$@" ;;
        "help"|"--help"|"-h") show_help ;;
        "") show_banner; show_help ;;
        *) error "Comando inválido: $command"; show_help; exit 1 ;;
    esac
}

main "$@"