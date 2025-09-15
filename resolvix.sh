#!/bin/bash

#######################################################
# Resolvix 
# Autor: Renylson Marques <renylsonm@gmail.com>
# GitHub: https://github.com/renylson/resolvix
# Versão: 2.0.0
#######################################################

set -e

# Cores para saída colorida
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'

# Variáveis globais
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="$SCRIPT_DIR/dashboard"
VERSION="2.0.0"

# Banner principal do projeto
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
    echo -e "${YELLOW}GitHub: https://github.com/renylson/resolvix${NC}"
    echo ""
}

# Funções de log
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERRO] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[AVISO] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCESSO] $1${NC}"
}

# Função para mostrar ajuda
show_help() {
    echo -e "${WHITE}RESOLVIX - Sistema Unificado de DNS Management${NC}"
    echo ""
    echo -e "${CYAN}USO:${NC}"
    echo "  $0 [COMANDO] [OPÇÕES]"
    echo ""
    echo -e "${CYAN}COMANDOS PRINCIPAIS:${NC}"
    echo -e "${YELLOW}  install${NC}         Instalar e configurar o sistema completo"
    echo -e "${YELLOW}  uninstall${NC}       Remover completamente o sistema"
    echo -e "${YELLOW}  status${NC}          Verificar status do sistema"
    echo -e "${YELLOW}  configure${NC}       Reconfigurar BIND9"
    echo ""
    echo -e "${CYAN}DASHBOARD:${NC}"
    echo -e "${YELLOW}  dashboard${NC}       Gerenciar dashboard web"
    echo -e "${YELLOW}  dashboard start${NC} Iniciar dashboard"
    echo -e "${YELLOW}  dashboard stop${NC}  Parar dashboard"
    echo -e "${YELLOW}  dashboard service${NC} Configurar como serviço"
    echo ""
    echo -e "${CYAN}SERVIÇOS:${NC}"
    echo -e "${YELLOW}  start${NC}           Iniciar serviços"
    echo -e "${YELLOW}  stop${NC}            Parar serviços"
    echo -e "${YELLOW}  restart${NC}         Reiniciar serviços"
    echo -e "${YELLOW}  logs${NC}            Visualizar logs"
    echo ""
    echo -e "${CYAN}DIAGNÓSTICOS:${NC}"
    echo -e "${YELLOW}  test${NC}            Testar resolução DNS"
    echo -e "${YELLOW}  monitor${NC}         Monitor em tempo real"
    echo -e "${YELLOW}  benchmark${NC}       Benchmark de performance"
    echo ""
    echo -e "${CYAN}EXEMPLOS:${NC}"
    echo "  $0 install           # Instalação completa"
    echo "  $0 dashboard start   # Iniciar dashboard"
    echo "  $0 status           # Verificar status"
    echo "  $0 test             # Testar DNS"
}

# Verificar privilégios de root quando necessário
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Esta operação precisa ser executada como root (use sudo)"
        exit 1
    fi
}

# Detectar distribuição Linux
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif command -v lsb_release >/dev/null 2>&1; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif [[ -f /etc/redhat-release ]]; then
        echo "centos"
    else
        echo "unknown"
    fi
}

# Instalar dependências baseado na distribuição
install_dependencies() {
    local distro=$(detect_distro)
    
    info "Detectada distribuição: $distro"
    
    # Verificar conectividade com a internet
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        error "Sem conectividade com a internet. Verifique sua conexão."
        exit 1
    fi
    
    info "Instalando dependências..."
    
    case $distro in
        ubuntu|debian)
            if ! apt-get update; then
                error "Falha ao atualizar repositórios"
                exit 1
            fi
            if ! apt-get install -y bind9 bind9-utils bind9-doc python3 python3-pip python3-venv curl bind9-dnsutils bc lsof; then
                error "Falha ao instalar dependências"
                exit 1
            fi
            ;;
        centos|rhel|fedora)
            if command -v dnf >/dev/null 2>&1; then
                if ! dnf install -y bind bind-utils python3 python3-pip curl bc lsof; then
                    error "Falha ao instalar dependências"
                    exit 1
                fi
            else
                if ! yum install -y bind bind-utils python3 python3-pip curl bc lsof; then
                    error "Falha ao instalar dependências"
                    exit 1
                fi
            fi
            ;;
        *)
            error "Distribuição não suportada: $distro"
            exit 1
            ;;
    esac
    
    success "Dependências instaladas com sucesso"
}

# Gerar configuração otimizada do BIND9
generate_bind_config() {
    local named_conf="/etc/bind/named.conf"
    local named_options="/etc/bind/named.conf.options"
    local named_local="/etc/bind/named.conf.local"
    local acl_conf="/etc/bind/acl.conf"
    
    info "Gerando configuração otimizada do BIND9..."
    
    # Backup da configuração existente
    if [[ -f "$named_conf" ]]; then
        cp "$named_conf" "${named_conf}.backup.$(date +%Y%m%d_%H%M%S)"
        log "Backup da configuração existente criado"
    fi
    
    # named.conf principal
    cat > "$named_conf" << 'EOF'
// Resolvix - Configuração Principal do BIND9
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/acl.conf";
EOF

    # Configuração de opções para alta performance
    cat > "$named_options" << 'EOF'
// Resolvix - Configurações Otimizadas para Alta Carga
options {
    directory "/var/cache/bind";
    
    // Escuta em todas as interfaces
    listen-on port 53 { any; };
    listen-on-v6 port 53 { any; };
    
    // Limites para alta performance
    recursive-clients 10000;
    tcp-clients 1000;
    clients-per-query 100;
    max-clients-per-query 200;
    
    // Cache otimizado
    max-cache-size 512M;
    max-cache-ttl 86400;
    max-ncache-ttl 3600;
    
    // Performance de rede
    edns-udp-size 4096;
    max-udp-size 4096;
    
    // Forwarders (Google DNS + Cloudflare)
    forwarders {
        8.8.8.8;
        8.8.4.4;
        1.1.1.1;
        1.0.0.1;
    };
    
    // Recursão
    recursion yes;
    allow-recursion { any; };
    
    // Consultas
    allow-query { any; };
    allow-transfer { none; };
    
    // DNS over TCP
    tcp-listen-queue 100;
    
    // DNSSEC
    dnssec-validation auto;
    
    // Logging
    version "Resolvix DNS Server";
    
    // Statistics file (rndc stats command)
    statistics-file "/var/cache/bind/named.stats";
    zone-statistics yes;
};

// Statistics channels for HTTP access (XML/JSON)
statistics-channels {
    inet 127.0.0.1 port 8053;
};

// Logging configuration
logging {
    channel bind_log {
        file "/var/log/bind/bind.log" versions 3 size 5m;
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

    # Configuração local
    cat > "$named_local" << 'EOF'
// Resolvix - Configurações Locais
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

    # ACL configuration
    cat > "$acl_conf" << 'EOF'
// Resolvix - Access Control Lists
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

    # Criar diretório de logs
    mkdir -p /var/log/bind
    chown bind:bind /var/log/bind
    
    # Verificar configuração
    if named-checkconf; then
        success "Configuração do BIND9 gerada com sucesso"
    else
        error "Erro na configuração do BIND9"
        exit 1
    fi
}

# Configurar dashboard
setup_dashboard() {
    info "Configurando dashboard web..."
    
    if [[ ! -d "$DASHBOARD_DIR" ]]; then
        error "Diretório dashboard não encontrado!"
        return 1
    fi
    
    cd "$DASHBOARD_DIR"
    
    # Verificar se requirements.txt existe
    if [[ ! -f "requirements.txt" ]]; then
        warning "Arquivo requirements.txt não encontrado, criando um básico..."
        cat > requirements.txt << 'EOF'
Flask==2.3.3
psutil==5.9.5
requests==2.31.0
EOF
    fi
    
    # Criar ambiente virtual se não existir
    if [[ ! -d "venv" ]]; then
        info "Criando ambiente virtual Python..."
        python3 -m venv venv
    fi
    
    # Ativar ambiente virtual e instalar dependências
    source venv/bin/activate
    pip install --upgrade pip
    if pip install -r requirements.txt; then
        success "Dependências do dashboard instaladas com sucesso"
    else
        error "Falha ao instalar dependências do dashboard"
        return 1
    fi
    
    success "Dashboard configurado com sucesso"
    cd "$SCRIPT_DIR"
}

# Configurar serviço systemd para dashboard
setup_dashboard_service() {
    check_root
    
    info "Configurando serviço systemd para dashboard..."
    
    local service_file="/etc/systemd/system/resolvix-dashboard.service"
    local dashboard_path="$DASHBOARD_DIR"
    local current_user="${SUDO_USER:-$USER}"
    
    # Criar usuário para o serviço se não existir
    # Não é necessário criar usuário separado, usaremos o usuário atual
    # O serviço systemd será executado com o usuário que instalou o sistema
    
    # Ajustar permissões para o usuário atual
    chown -R $USER:$USER "$dashboard_path"
    
    cat > "$service_file" << EOF
[Unit]
Description=Resolvix DNS Dashboard
Documentation=https://github.com/renylson/resolvix
After=network.target bind9.service
Requires=bind9.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$dashboard_path
Environment=PATH=$dashboard_path/venv/bin
ExecStart=$dashboard_path/venv/bin/python $dashboard_path/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable resolvix-dashboard
    
    success "Serviço dashboard configurado"
}

# Função principal de instalação
install_system() {
    show_banner
    log "Iniciando instalação do Resolvix DNS Server..."
    
    check_root
    
    # Verificar se já está instalado
    if systemctl is-active --quiet bind9 && systemctl is-active --quiet resolvix-dashboard; then
        warning "Sistema já parece estar instalado e rodando."
        read -p "Deseja reinstalar? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Instalação cancelada."
            exit 0
        fi
    fi
    
    install_dependencies
    generate_bind_config
    
    # Configurar BIND9
    systemctl enable bind9 2>/dev/null || true
    if ! systemctl restart bind9; then
        error "Falha ao iniciar BIND9. Verifique os logs."
        exit 1
    fi
    
    # Configurar dashboard
    if ! setup_dashboard; then
        error "Falha ao configurar dashboard"
        exit 1
    fi
    
    setup_dashboard_service
    
    # Iniciar serviços
    if ! systemctl start resolvix-dashboard; then
        warning "Falha ao iniciar dashboard. Tentando novamente..."
        sleep 3
        systemctl start resolvix-dashboard || true
    fi
    
    # Teste final
    sleep 5
    if systemctl is-active --quiet bind9 && systemctl is-active --quiet resolvix-dashboard; then
        success "Instalação concluída com sucesso!"
        echo ""
        info "Serviços disponíveis:"
        echo "  - DNS Server: porta 53"
        echo "  - Statistics: http://127.0.0.1:8053"
        echo "  - Dashboard: http://127.0.0.1:5000"
        echo ""
        info "Comandos úteis:"
        echo "  - Status: $0 status"
        echo "  - Logs: $0 logs"
        echo "  - Teste: $0 test"
    else
        error "Falha na instalação. Verifique os logs."
        echo ""
        info "Para diagnóstico:"
        echo "  - systemctl status bind9"
        echo "  - systemctl status resolvix-dashboard"
        echo "  - journalctl -u bind9 -n 20"
        echo "  - journalctl -u resolvix-dashboard -n 20"
        exit 1
    fi
}

# Verificar status do sistema
check_status() {
    show_banner
    info "Verificando status do Resolvix DNS Server..."
    echo ""
    
    # Verificar BIND9
    if systemctl is-active --quiet bind9; then
        echo -e "${GREEN}✓ BIND9 está rodando${NC}"
        local bind_status="UP"
    else
        echo -e "${RED}✗ BIND9 não está rodando${NC}"
        local bind_status="DOWN"
    fi
    
    # Verificar Dashboard
    if systemctl is-active --quiet resolvix-dashboard; then
        echo -e "${GREEN}✓ Dashboard está rodando${NC}"
        local dashboard_status="UP"
    else
        echo -e "${RED}✗ Dashboard não está rodando${NC}"
        local dashboard_status="DOWN"
    fi
    
    # Verificar configuração
    if named-checkconf 2>/dev/null; then
        echo -e "${GREEN}✓ Configuração é válida${NC}"
    else
        echo -e "${RED}✗ Configuração tem erros${NC}"
    fi
    
    # Teste de resolução DNS
    if timeout 5 dig @127.0.0.1 google.com A +short > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Resolução DNS está funcionando${NC}"
    else
        echo -e "${RED}✗ Resolução DNS falhou${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Informações detalhadas:${NC}"
    
    if [[ "$bind_status" == "UP" ]]; then
        echo "  BIND9:"
        echo "    Status: $(systemctl is-active bind9)"
        echo "    Uptime: $(systemctl show bind9 --property=ActiveEnterTimestamp --value | cut -d' ' -f2- 2>/dev/null || echo "N/A")"
        echo "    PID: $(systemctl show bind9 --property=MainPID --value 2>/dev/null || echo "N/A")"
    fi
    
    if [[ "$dashboard_status" == "UP" ]]; then
        echo "  Dashboard:"
        echo "    Status: $(systemctl is-active resolvix-dashboard)"
        echo "    URL: http://127.0.0.1:5000"
    fi
    
    echo "  Sistema:"
    echo "    CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')"
    echo "    Memória: $(free -m | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
    echo "    Conexões :53: $(ss -tuln | grep ":53" | wc -l)"
}

# Testar resolução DNS
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

# Gerenciar dashboard
manage_dashboard() {
    local action="$1"
    
    case "$action" in
        "start")
            info "Iniciando dashboard..."
            if [[ -d "$DASHBOARD_DIR" ]]; then
                check_root
                systemctl start resolvix-dashboard
                success "Dashboard iniciado"
                info "Acesse: http://127.0.0.1:5000"
            else
                error "Dashboard não está instalado"
            fi
            ;;
        "stop")
            info "Parando dashboard..."
            check_root
            systemctl stop resolvix-dashboard
            success "Dashboard parado"
            ;;
        "service")
            setup_dashboard_service
            ;;
        "logs")
            journalctl -u resolvix-dashboard -f
            ;;
        "status")
            if systemctl is-active --quiet resolvix-dashboard; then
                success "Dashboard está rodando"
                info "URL: http://127.0.0.1:5000"
            else
                warning "Dashboard não está rodando"
            fi
            ;;
        "restart")
            info "Reiniciando dashboard..."
            check_root
            systemctl restart resolvix-dashboard
            success "Dashboard reiniciado"
            ;;
        *)
            echo -e "${YELLOW}Opções do dashboard:${NC}"
            echo "  start   - Iniciar dashboard"
            echo "  stop    - Parar dashboard"
            echo "  restart - Reiniciar dashboard"
            echo "  status  - Verificar status"
            echo "  service - Configurar como serviço"
            echo "  logs    - Ver logs"
            ;;
    esac
}

# Desinstalar sistema
uninstall_system() {
    warning "Isso removerá o servidor DNS Resolvix e todas as configurações."
    warning "Arquivos de backup serão preservados."
    echo ""
    read -p "Tem certeza que deseja continuar? (y/N): " -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Desinstalação cancelada."
        exit 0
    fi
    
    check_root
    
    info "Removendo Resolvix DNS Server..."
    
    # Parar e desabilitar serviços
    info "Parando serviços..."
    systemctl stop resolvix-dashboard 2>/dev/null || true
    systemctl disable resolvix-dashboard 2>/dev/null || true
    systemctl stop bind9 2>/dev/null || true
    systemctl stop named 2>/dev/null || true
    systemctl disable bind9 2>/dev/null || true
    systemctl disable named 2>/dev/null || true
    
    # Matar processos que possam estar usando as portas
    info "Liberando portas em uso..."
    pkill -f "python.*app.py" 2>/dev/null || true
    pkill -f "named" 2>/dev/null || true
    sleep 2
    
    # Forçar liberação da porta 5000 se necessário
    local port_5000_pid=$(lsof -ti:5000 2>/dev/null || true)
    if [[ -n "$port_5000_pid" ]]; then
        kill -9 $port_5000_pid 2>/dev/null || true
        warning "Processo na porta 5000 foi terminado forçadamente"
    fi
    
    # Remover arquivos de serviço
    info "Removendo serviços do systemd..."
    rm -f /etc/systemd/system/resolvix-dashboard.service
    systemctl daemon-reload
    
    # Backup e remoção de configurações
    local backup_dir="/root/resolvix-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    if [[ -f /etc/bind/named.conf ]]; then
        cp -r /etc/bind/* "$backup_dir/" 2>/dev/null || true
        info "Backup das configurações salvo em: $backup_dir"
    fi
    
    # Remover diretórios de configuração e cache
    info "Removendo diretórios de configuração..."
    rm -rf /etc/bind /var/cache/bind /var/log/bind
    
    # Remover ambiente virtual do dashboard
    info "Removendo ambiente virtual do dashboard..."
    rm -rf "$DASHBOARD_DIR/venv"
    
    # Remover pacotes (opcional)
    echo ""
    read -p "Remover também o BIND9 e dependências? (y/N): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Removendo pacotes do BIND9..."
        local distro=$(detect_distro)
        case $distro in
            ubuntu|debian)
                apt-get remove --purge -y bind9 bind9-utils bind9-doc bind9-libs bind9-dnsutils bind9-host 2>/dev/null || true
                apt-get autoremove -y 2>/dev/null || true
                ;;
            centos|rhel|fedora)
                if command -v dnf >/dev/null 2>&1; then
                    dnf remove -y bind bind-utils 2>/dev/null || true
                else
                    yum remove -y bind bind-utils 2>/dev/null || true
                fi
                ;;
        esac
    fi
    
    # Remover usuário do serviço
    if id "resolvix" &>/dev/null; then
        info "Removendo usuário resolvix..."
        userdel resolvix 2>/dev/null || true
        rm -rf /var/lib/resolvix 2>/dev/null || true
    fi
    
    # Limpeza final
    info "Fazendo limpeza final..."
    systemctl daemon-reload
    
    # Verificar se as portas foram liberadas
    if ss -tlnp | grep -q ":53\|:5000"; then
        warning "Algumas portas ainda podem estar em uso. Reinicie o sistema se necessário."
    fi
    
    success "Resolvix DNS Server removido com sucesso"
    info "Backup salvo em: $backup_dir"
    echo ""
    info "Para uma limpeza completa, considere reiniciar o sistema."
}

# Monitor em tempo real
monitor_system() {
    info "Iniciando monitor em tempo real (Ctrl+C para sair)..."
    echo ""
    
    while true; do
        clear
        echo -e "${CYAN}=== Resolvix DNS Monitor - $(date) ===${NC}"
        echo ""
        
        # Status dos serviços
        if systemctl is-active --quiet bind9; then
            echo -e "${GREEN}✓ BIND9: Ativo${NC}"
        else
            echo -e "${RED}✗ BIND9: Inativo${NC}"
        fi
        
        if systemctl is-active --quiet resolvix-dashboard; then
            echo -e "${GREEN}✓ Dashboard: Ativo${NC}"
        else
            echo -e "${RED}✗ Dashboard: Inativo${NC}"
        fi
        
        echo ""
        
        # Estatísticas do sistema
        echo -e "${BLUE}Sistema:${NC}"
        echo "  CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')"
        echo "  Memória: $(free -m | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
        echo "  Load: $(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')"
        echo "  Conexões DNS: $(ss -tuln | grep ":53" | wc -l)"
        
        echo ""
        
        # Teste rápido de DNS
        echo -e "${BLUE}Teste DNS:${NC}"
        local start_time=$(date +%s.%N)
        if dig @127.0.0.1 google.com A +short +time=2 >/dev/null 2>&1; then
            local end_time=$(date +%s.%N)
            local duration=$(echo "($end_time - $start_time) * 1000" | bc | cut -d. -f1)
            echo -e "  ${GREEN}✓ Resolução: ${duration}ms${NC}"
        else
            echo -e "  ${RED}✗ Resolução: Falhou${NC}"
        fi
        
        echo ""
        echo -e "${GRAY}Pressione Ctrl+C para sair${NC}"
        
        sleep 3
    done
}

# Função principal
main() {
    local command="$1"
    shift 2>/dev/null || true
    
    case "$command" in
        "install")
            install_system
            ;;
        "uninstall")
            uninstall_system
            ;;
        "status")
            check_status
            ;;
        "configure")
            check_root
            generate_bind_config
            systemctl restart bind9
            success "Reconfiguração concluída"
            ;;
        "dashboard")
            manage_dashboard "$1"
            ;;
        "start")
            check_root
            systemctl start bind9 resolvix-dashboard
            success "Serviços iniciados"
            ;;
        "stop")
            check_root
            systemctl stop bind9 resolvix-dashboard
            success "Serviços parados"
            ;;
        "restart")
            check_root
            systemctl restart bind9 resolvix-dashboard
            success "Serviços reiniciados"
            ;;
        "logs")
            if [[ "$1" == "dashboard" ]]; then
                journalctl -u resolvix-dashboard -f
            else
                journalctl -u bind9 -f
            fi
            ;;
        "test")
            test_dns
            ;;
        "monitor")
            monitor_system
            ;;
        "benchmark")
            if [[ -f "$SCRIPT_DIR/dns_stress_test.sh" ]]; then
                if [[ -x "$SCRIPT_DIR/dns_stress_test.sh" ]]; then
                    "$SCRIPT_DIR/dns_stress_test.sh" "$@"
                else
                    chmod +x "$SCRIPT_DIR/dns_stress_test.sh"
                    "$SCRIPT_DIR/dns_stress_test.sh" "$@"
                fi
            else
                error "Script de benchmark não encontrado: $SCRIPT_DIR/dns_stress_test.sh"
                info "Verifique se o arquivo existe e tem permissões de execução"
            fi
            ;;
        "help"|"--help"|"-h"|"")
            show_help
            ;;
        *)
            error "Comando inválido: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Trap para limpeza
trap 'echo -e "\n${YELLOW}Operação interrompida${NC}"; exit 130' INT

# Executar função principal
main "$@"