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
    echo -e "${YELLOW}  dashboard${NC}       Gerenciar dashboard (start|stop|restart|status|logs|password)"
    echo ""
    echo -e "${CYAN}EXEMPLOS:${NC}"
    echo -e "  $0 install                 # Instalar sistema"
    echo -e "  $0 dashboard password      # Alterar senha do dashboard"
    echo -e "  $0 dashboard status        # Status do dashboard"
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

detect_bind_service() {
    # Detectar qual é o nome correto do serviço BIND
    if systemctl list-unit-files | grep -q "^bind9.service"; then
        echo "bind9"
    elif systemctl list-unit-files | grep -q "^named.service"; then
        echo "named"
    elif [[ -f /etc/systemd/system/bind9.service ]] || [[ -f /usr/lib/systemd/system/bind9.service ]]; then
        echo "bind9"
    elif [[ -f /etc/systemd/system/named.service ]] || [[ -f /usr/lib/systemd/system/named.service ]]; then
        echo "named"
    else
        # Tentar detectar pelo executável
        if command -v named >/dev/null 2>&1; then
            echo "named"
        else
            echo "bind9"
        fi
    fi
}

create_resolvix_user() {
    local username="resolvix"
    
    if id "$username" &>/dev/null; then
        info "Usuário resolvix já existe"
    else
        info "Criando usuário resolvix..."
        useradd -r -s /bin/false -c "ResolvIX System User" -d /var/lib/resolvix "$username"
        usermod -a -G bind "$username"
    fi
    
    mkdir -p /var/lib/resolvix /var/log/resolvix /var/backups/resolvix
    mkdir -p /var/log/named /var/cache/bind
    
    chown "$username:$username" /var/lib/resolvix
    chown -R "$username:bind" /var/log/resolvix /var/backups/resolvix
    chown bind:bind /var/log/named /var/cache/bind
    
    chmod 750 /var/lib/resolvix
    chmod -R 775 /var/log/resolvix /var/backups/resolvix
    chmod 755 /var/log/named /var/cache/bind
    
    touch /var/log/resolvix/dashboard.log
    chown resolvix:bind /var/log/resolvix/dashboard.log
    chmod 664 /var/log/resolvix/dashboard.log
}

install_dependencies() {
    local distro=$(detect_distro)
    
    info "Instalando dependências..."
    info "Distribuição detectada: $distro"
    
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        error "Sem conectividade com a internet"
        exit 1
    fi
    
    case $distro in
        ubuntu|debian)
            apt-get update
            apt-get install -y bind9 bind9-utils python3 python3-pip python3-venv curl bind9-dnsutils bc lsof
            
            # Parar o serviço se estiver rodando para reconfigurar
            systemctl stop systemd-resolved 2>/dev/null || true
            systemctl disable systemd-resolved 2>/dev/null || true
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y bind bind-utils python3 python3-pip curl bc lsof
            else
                yum install -y bind bind-utils python3 python3-pip curl bc lsof
            fi
            
            # Configurar firewall se ativo
            if systemctl is-active --quiet firewalld; then
                firewall-cmd --permanent --add-service=dns 2>/dev/null || true
                firewall-cmd --permanent --add-port=5000/tcp 2>/dev/null || true
                firewall-cmd --permanent --add-port=8053/tcp 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true
            fi
            ;;
        opensuse*|suse)
            zypper refresh
            zypper install -y bind bind-utils python3 python3-pip curl bc lsof
            ;;
        arch)
            pacman -Sy --noconfirm bind python python-pip curl bc lsof
            ;;
        *)
            warning "Distribuição não totalmente suportada: $distro"
            warning "Tentando instalação genérica..."
            
            # Tentar diferentes gerenciadores de pacote
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update
                apt-get install -y bind9 bind9-utils python3 python3-pip python3-venv curl bind9-dnsutils bc lsof
            elif command -v yum >/dev/null 2>&1; then
                yum install -y bind bind-utils python3 python3-pip curl bc lsof
            elif command -v zypper >/dev/null 2>&1; then
                zypper install -y bind bind-utils python3 python3-pip curl bc lsof
            else
                error "Gerenciador de pacotes não suportado"
                exit 1
            fi
            ;;
    esac
    
    # Verificar se Python3 está disponível
    if ! command -v python3 >/dev/null 2>&1; then
        error "Python3 não foi instalado corretamente"
        exit 1
    fi
    
    # Verificar se pip está disponível
    if ! command -v pip3 >/dev/null 2>&1 && ! python3 -m pip --version >/dev/null 2>&1; then
        error "pip3 não foi instalado corretamente"
        exit 1
    fi
}

generate_bind_config() {
    info "Configurando BIND9..."
    
    # Criar diretórios necessários
    mkdir -p /etc/bind /var/cache/bind /var/log/named
    chown bind:bind /var/cache/bind /var/log/named
    
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


    create_default_zone_files
    
   
    chown -R bind:bind /etc/bind /var/cache/bind /var/log/named
    chmod -R 644 /etc/bind/*
    chmod 755 /etc/bind /var/cache/bind /var/log/named
    
    if ! named-checkconf; then
        error "Erro na configuração do BIND9"
        exit 1
    fi
}

create_default_zone_files() {
    info "Criando arquivos de zona padrão..."
    
    # db.local
    if [[ ! -f /etc/bind/db.local ]]; then
        cat > /etc/bind/db.local << 'EOF'
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.
@       IN      A       127.0.0.1
@       IN      AAAA    ::1
EOF
    fi
    
    # db.127
    if [[ ! -f /etc/bind/db.127 ]]; then
        cat > /etc/bind/db.127 << 'EOF'
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.
1.0.0   IN      PTR     localhost.
EOF
    fi
    
    # db.0
    if [[ ! -f /etc/bind/db.0 ]]; then
        cat > /etc/bind/db.0 << 'EOF'
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.
EOF
    fi
    
    # db.255
    if [[ ! -f /etc/bind/db.255 ]]; then
        cat > /etc/bind/db.255 << 'EOF'
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.
EOF
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
    
    # Limpar dados existentes durante instalação
    if [[ -d "$DASHBOARD_DIR/data" ]]; then
        info "Limpando credenciais existentes..."
        rm -rf "$DASHBOARD_DIR/data"
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

reconfigure_admin_credentials() {
    info "Reconfigurando credenciais do administrador..."
    
    if [[ -f "$DASHBOARD_DIR/data/credentials.json" ]]; then
        warning "Credenciais já configuradas"
        read -p "Reconfigurar? (y/N): " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && return 0
        
        info "Removendo credenciais existentes..."
        rm -rf "$DASHBOARD_DIR/data"
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
    
    systemctl restart resolvix-dashboard 2>/dev/null || true
    
    cd "$SCRIPT_DIR"
}

setup_dashboard_service() {
    info "Configurando serviço systemd..."
    
    # Garantir que os diretórios existem
    mkdir -p /var/log/resolvix
    chown -R resolvix:bind /var/log/resolvix
    chmod -R 775 /var/log/resolvix
    
    # Criar arquivo de log com permissões corretas
    touch /var/log/resolvix/dashboard.log
    chown resolvix:bind /var/log/resolvix/dashboard.log
    chmod 664 /var/log/resolvix/dashboard.log
    
    # Configurar permissões do dashboard
    chown -R resolvix:bind "$DASHBOARD_DIR"
    chmod -R 755 "$DASHBOARD_DIR"
    
    # Configurar ACL se existir
    if [[ -f /etc/bind/acl.conf ]]; then
        chown :bind /etc/bind/acl.conf
        chmod 664 /etc/bind/acl.conf
    fi
    
    cat > /etc/systemd/system/resolvix-dashboard.service << EOF
[Unit]
Description=Resolvix DNS Dashboard
After=network.target named.service
Wants=named.service

[Service]
Type=simple
User=resolvix
Group=bind
WorkingDirectory=$DASHBOARD_DIR
Environment=PATH=$DASHBOARD_DIR/venv/bin
Environment=PYTHONPATH=$DASHBOARD_DIR
Environment=LOG_FILE=/var/log/resolvix/dashboard.log
ExecStartPre=/bin/mkdir -p /var/log/resolvix
ExecStartPre=/bin/touch /var/log/resolvix/dashboard.log
ExecStartPre=/bin/chown resolvix:bind /var/log/resolvix/dashboard.log
ExecStart=$DASHBOARD_DIR/venv/bin/python $DASHBOARD_DIR/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SupplementaryGroups=bind
UMask=0002

# Configurações de segurança
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/resolvix $DASHBOARD_DIR/data
PrivateTmp=true

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
    
    # Detectar serviço BIND correto
    local bind_service=$(detect_bind_service)
    info "Serviço BIND detectado: $bind_service"
    
    if systemctl is-active --quiet "$bind_service" && systemctl is-active --quiet resolvix-dashboard; then
        warning "Sistema já instalado"
        read -p "Reinstalar? (y/N): " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    fi
    
    install_dependencies
    create_resolvix_user
    generate_bind_config
    
    # Parar serviços conflitantes
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    
    # Configurar e iniciar BIND
    systemctl enable "$bind_service" 2>/dev/null || true
    systemctl restart "$bind_service" || { error "Falha ao iniciar BIND9 ($bind_service)"; exit 1; }
    
    setup_dashboard || { error "Falha ao configurar dashboard"; exit 1; }
    setup_dashboard_service
    create_global_command
    
    # Tentar iniciar dashboard com retry
    local retry_count=0
    while [[ $retry_count -lt 3 ]]; do
        if systemctl start resolvix-dashboard; then
            break
        else
            warning "Tentativa $((retry_count + 1)) de iniciar dashboard falhou"
            sleep 3
            ((retry_count++))
        fi
    done
    
    sleep 5
    if systemctl is-active --quiet "$bind_service" && systemctl is-active --quiet resolvix-dashboard; then
        success "Instalação concluída!"
        echo ""
        info "Serviços:"
        echo "  - DNS Server ($bind_service): porta 53"
        echo "  - Statistics: http://127.0.0.1:8053"
        echo "  - Dashboard: http://127.0.0.1:5000"
    else
        error "Falha na instalação"
        warning "Verifique os logs com: journalctl -u resolvix-dashboard"
        exit 1
    fi
}

check_status() {
    show_banner
    info "Status do Resolvix DNS Server..."
    echo ""
    
    local bind_service=$(detect_bind_service)
    
    systemctl is-active --quiet "$bind_service" && echo -e "${GREEN}✓ BIND9 ($bind_service) rodando${NC}" || echo -e "${RED}✗ BIND9 ($bind_service) parado${NC}"
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
        "password"|"passwd") reconfigure_admin_credentials ;;
        *) 
            echo -e "${YELLOW}Opções: start|stop|restart|status|logs|password${NC}" ;;
    esac
}

uninstall_system() {
    warning "Isso removerá o Resolvix DNS Server completamente"
    read -p "Continuar? (y/N): " -r
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    
    check_root
    info "Removendo Resolvix..."
    
    local bind_service=$(detect_bind_service)
    
    systemctl stop resolvix-dashboard "$bind_service" 2>/dev/null || true
    systemctl disable resolvix-dashboard "$bind_service" 2>/dev/null || true
    
    pkill -f "python.*app.py" 2>/dev/null || true
    pkill -f "named" 2>/dev/null || true
    
    rm -f /etc/systemd/system/resolvix-dashboard.service
    systemctl daemon-reload
    
    local backup_dir="/root/resolvix-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    [[ -f /etc/bind/named.conf ]] && cp -r /etc/bind/* "$backup_dir/" 2>/dev/null
    
    rm -rf /etc/bind /var/cache/bind /var/log/bind /var/log/resolvix "$INSTALL_DIR"
    
    if id "resolvix" &>/dev/null; then
        userdel resolvix 2>/dev/null || true
        rm -rf /var/lib/resolvix /var/backups/resolvix 2>/dev/null || true
    fi
    
    rm -f /usr/local/bin/resolvix
    
    success "Resolvix removido - Backup em: $backup_dir"
}

main() {
    local command="$1"
    shift 2>/dev/null || true
    
    # Detectar serviço BIND para comandos que precisam
    local bind_service=""
    if [[ "$command" =~ ^(start|stop|restart|logs)$ ]]; then
        bind_service=$(detect_bind_service)
    fi
    
    case "$command" in
        "install") install_system ;;
        "uninstall") uninstall_system ;;
        "status") check_status ;;
        "start") check_root; systemctl start "$bind_service" resolvix-dashboard; success "Serviços iniciados" ;;
        "stop") check_root; systemctl stop "$bind_service" resolvix-dashboard; success "Serviços parados" ;;
        "restart") check_root; systemctl restart "$bind_service" resolvix-dashboard; success "Serviços reiniciados" ;;
        "test") test_dns ;;
        "logs") 
            echo -e "${CYAN}Logs do BIND9 ($bind_service):${NC}"
            journalctl -u "$bind_service" -n 10 --no-pager
            echo -e "${CYAN}Logs do Dashboard:${NC}"
            journalctl -u resolvix-dashboard -n 10 --no-pager ;;
        "dashboard") manage_dashboard "$@" ;;
        "help"|"--help"|"-h") show_help ;;
        "") show_banner; show_help ;;
        *) error "Comando inválido: $command"; show_help; exit 1 ;;
    esac
}

main "$@"