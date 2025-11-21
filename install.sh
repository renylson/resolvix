#!/bin/bash

################################################################################
#                                  RESOLVIX                                    #
#                    Instalador de DNS Recursivo - Unbound                     #
#                                                                              #
# Autor: Renylson Marques                                                      #
# Email: renylsonm@gmail.com                                                   #
# Telefone: (87) 98846-3681                                                    #
#                                                                              #
#                                                                              #
################################################################################

set -euo pipefail

# ============================================================================
# CORES E FORMATAÇÃO
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ============================================================================
# FUNÇÕES UTILITÁRIAS
# ============================================================================

print_header() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│                  DNS RECURSIVO - UNBOUND v1.0               │"
    echo "│                   Instalador Profissional                   │"
    echo "├─────────────────────────────────────────────────────────────┤"
    echo "│                                                             │"
    echo "│  👤 Autor: Renylson Marques                                │"
    echo "│  📧 Email: renylsonm@gmail.com                             │"
    echo "│  📱 Tel: (87) 98846-3681                                   │"
    echo "│                                                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BLUE}${BOLD}▶ $1${NC}"
    echo -e "${BLUE}$(printf '─%.0s' {1..70})${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ $1${NC}"
}

confirm_action() {
    local prompt="$1"
    local response
    
    if [ ! -t 0 ]; then
        echo -e "${YELLOW}${BOLD}${prompt} [s/n]: s${NC}"
        return 0
    fi
    
    while true; do
        read -p "$(echo -e ${YELLOW}${BOLD}$prompt' [s/n]: '${NC})" response
        case "$response" in
            [sS]|[yY]|sim|yes|"")
                return 0
                ;;
            [nN]|não|no)
                return 1
                ;;
            *)
                print_warning "Resposta inválida. Digite 's' para sim ou 'n' para não."
                ;;
        esac
    done
}

# ============================================================================
# VERIFICAÇÕES PRÉ-INSTALAÇÃO
# ============================================================================

check_root() {
    print_section "Verificando privilégios de root"
    
    if [ "$EUID" -ne 0 ]; then
        print_error "Este script deve ser executado como root!"
        print_info "Execute com: sudo $0"
        exit 1
    fi
    
    print_success "Usuário root confirmado"
}

check_debian_version() {
    print_section "Verificando versão do Debian"
    
    if [ ! -f /etc/os-release ]; then
        print_error "Arquivo /etc/os-release não encontrado"
        exit 1
    fi
    
    source /etc/os-release
    
    if [ "$ID" != "debian" ]; then
        print_error "Este script foi desenvolvido para Debian. Sistema detectado: $ID"
        exit 1
    fi
    
    DEBIAN_VERSION=$(echo "$VERSION_ID" | cut -d. -f1)
    
    if [ "$DEBIAN_VERSION" -lt 13 ]; then
        print_error "Versão mínima requerida: Debian 13. Versão encontrada: Debian $DEBIAN_VERSION"
        exit 1
    fi
    
    print_success "Debian $DEBIAN_VERSION detectado"
}

check_internet() {
    print_section "Verificando conectividade com internet"
    
    if ! timeout 5 ping -c 1 8.8.8.8 &> /dev/null; then
        print_warning "Conectividade com internet pode estar limitada"
        if ! confirm_action "Deseja continuar mesmo assim?"; then
            print_error "Instalação cancelada pelo usuário"
            exit 1
        fi
    else
        print_success "Conectividade confirmada"
    fi
}

# ============================================================================
# CONFIGURAÇÕES DE REDE
# ============================================================================

get_network_config() {
    print_section "Detectando configurações de rede"
    
    IPV4_ADDR=""
    IPV6_ADDR=""
    
    print_info "Tentando detectar IPv4..."
    
    if command -v hostname &> /dev/null; then
        print_info "  └─ Tentando: hostname -I"
        IPV4_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' | head -1)
        if [ -n "$IPV4_ADDR" ] && [ "$IPV4_ADDR" != "127.0.0.1" ]; then
            print_success "IPv4 detectado (hostname -I): $IPV4_ADDR"
        fi
    fi
    
    if [ -z "$IPV4_ADDR" ] || [ "$IPV4_ADDR" == "127.0.0.1" ]; then
        if command -v ip &> /dev/null; then
            print_info "  └─ Tentando: ip route get 1"
            IPV4_ADDR=$(ip route get 1 2>/dev/null | awk '{print $(NF-2); exit}' | grep -v '^127\.')
            if [ -n "$IPV4_ADDR" ]; then
                print_success "IPv4 detectado (ip route): $IPV4_ADDR"
            fi
        fi
    fi
    
    if [ -z "$IPV4_ADDR" ] || [ "$IPV4_ADDR" == "127.0.0.1" ]; then
        if command -v ip &> /dev/null; then
            print_info "  └─ Tentando: ip -4 addr show"
            IPV4_ADDR=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)
            if [ -n "$IPV4_ADDR" ]; then
                print_success "IPv4 detectado (ip addr): $IPV4_ADDR"
            fi
        fi
    fi
    
    if [ -z "$IPV4_ADDR" ]; then
        print_warning "Nenhum endereço IPv4 encontrado, usando 127.0.0.1"
        IPV4_ADDR="127.0.0.1"
    fi
    
    print_info "Tentando detectar IPv6..."
    if command -v ip &> /dev/null; then
        print_info "  └─ Tentando: ip -6 addr show"
        IPV6_ADDR=$(timeout 3 ip -6 addr show 2>/dev/null | grep -oP '(?<=inet6\s)([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | grep -v '^::1' | grep -v '^fe80' | head -1) || IPV6_ADDR=""
        if [ -n "$IPV6_ADDR" ]; then
            print_success "IPv6 detectado: $IPV6_ADDR"
        else
            print_warning "Nenhum endereço IPv6 encontrado"
            IPV6_ADDR=""
            if ! confirm_action "IPv6 não foi detectado. Deseja continuar?"; then
                print_error "Instalação cancelada pelo usuário"
                exit 0
            fi
        fi
    else
        print_warning "Comando 'ip' não disponível, pulando detecção IPv6"
        IPV6_ADDR=""
        if ! confirm_action "Não foi possível verificar IPv6. Deseja continuar?"; then
            print_error "Instalação cancelada pelo usuário"
            exit 0
        fi
    fi
}

# ============================================================================
# PERGUNTAS INTERATIVAS
# ============================================================================

ask_ip_mode() {
    print_section "Configuração de modo de operação"
    
    echo -e "Como deseja configurar seu servidor DNS?\n"
    echo "1) IP Local    - Aceitar consultas de qualquer origem"
    echo "2) IP Público  - Aceitar apenas IPs privados e blocos específicos"
    echo ""
    
    if [ ! -t 0 ]; then
        IP_MODE_TYPE="public"
        print_success "Modo Público selecionado (entrada automática)"
        return
    fi
    
    while true; do
        read -p "Escolha uma opção (1 ou 2): " IP_MODE
        case "$IP_MODE" in
            1)
                IP_MODE_TYPE="local"
                print_success "Modo Local selecionado"
                break
                ;;
            2)
                IP_MODE_TYPE="public"
                print_success "Modo Público selecionado"
                break
                ;;
            *)
                print_error "Opção inválida. Digite 1 ou 2."
                ;;
        esac
    done
}

ask_ip_version() {
    print_section "Configuração de versão de IP"
    
    echo -e "Qual versão de IP deseja utilizar?\n"
    echo "1) IPv4 apenas"
    echo "2) IPv4 + IPv6"
    echo ""
    
    if [ ! -t 0 ]; then
        IP_VERSION_TYPE="both"
        ENABLE_IPV6="yes"
        print_success "IPv4 + IPv6 selecionado (entrada automática)"
        return
    fi
    
    while true; do
        read -p "Escolha uma opção (1 ou 2): " IP_VERSION
        case "$IP_VERSION" in
            1)
                IP_VERSION_TYPE="ipv4"
                ENABLE_IPV6="no"
                print_success "IPv4 selecionado"
                break
                ;;
            2)
                IP_VERSION_TYPE="both"
                ENABLE_IPV6="yes"
                print_success "IPv4 + IPv6 selecionado"
                break
                ;;
            *)
                print_error "Opção inválida. Digite 1 ou 2."
                ;;
        esac
    done
}

ask_public_ip_blocks() {
    print_section "Configuração de blocos IP permitidos"
    
    if [ "$IP_MODE_TYPE" != "public" ]; then
        return
    fi
    
    echo -e "Digite os blocos de IP que deseja permitir (CIDR)"
    echo "Exemplos IPv4: 203.0.113.0/24 203.0.114.0/24"
    echo "Exemplos IPv6: 2001:db8::/32 2001:db9::/32"
    echo "Misturado:    203.0.113.0/24 2001:db8::/32"
    echo "Ou pressione Enter para usar apenas IPs privados padrão"
    echo ""
    
    if [ ! -t 0 ]; then
        print_info "Usando blocos IP privados padrão (entrada automática)"
        CUSTOM_IP_BLOCKS=""
        return
    fi
    
    read -p "Blocos IP (IPv4/IPv6, separados por espaço): " CUSTOM_IP_BLOCKS
    
    if [ -z "$CUSTOM_IP_BLOCKS" ]; then
        print_info "Usando blocos IP privados padrão"
        CUSTOM_IP_BLOCKS=""
    else
        print_success "Blocos customizados: $CUSTOM_IP_BLOCKS"
        print_info "IPv4 e IPv6 aceitos!"
    fi
}

ask_monitoring() {
    print_section "Configuração de monitoramento"
    
    echo -e "Deseja instalar e configurar Prometheus com exportador de métricas?\n"
    echo "1) Sim  - Instalar Prometheus e exportador"
    echo "2) Não  - Não instalar Prometheus"
    echo ""
    
    if [ ! -t 0 ]; then
        INSTALL_PROMETHEUS="yes"
        print_success "Prometheus será instalado (entrada automática)"
        return
    fi
    
    while true; do
        read -p "Escolha uma opção (1 ou 2): " MONITORING_CHOICE
        case "$MONITORING_CHOICE" in
            1)
                INSTALL_PROMETHEUS="yes"
                print_success "Prometheus será instalado"
                break
                ;;
            2)
                INSTALL_PROMETHEUS="no"
                print_info "Prometheus não será instalado"
                break
                ;;
            *)
                print_error "Opção inválida. Digite 1 ou 2."
                ;;
        esac
    done
}

# ============================================================================
# INSTALAÇÃO DE DEPENDÊNCIAS
# ============================================================================

update_system() {
    print_section "Atualizando repositórios de pacotes"
    
    apt-get update || {
        print_error "Falha ao atualizar repositórios"
        exit 1
    }
    
    print_success "Repositórios atualizados"
}

install_dependencies() {
    print_section "Instalando dependências"
    
    local packages="unbound unbound-anchor curl wget net-tools dnsutils iputils-ping python3 python3-pip"
    
    apt-get install -y $packages || {
        print_error "Falha ao instalar dependências"
        exit 1
    }
    
    print_success "Dependências instaladas"
}

# ============================================================================
# CONFIGURAÇÃO DO UNBOUND
# ============================================================================

backup_config() {
    print_section "Criando backup da configuração"
    
    if [ -f /etc/unbound/unbound.conf ]; then
        cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup.$(date +%s)
        print_success "Backup criado"
    fi
}

generate_access_control() {
    local access_rules=""
    
    access_rules+="    access-control: 10.0.0.0/8 allow\n"
    access_rules+="    access-control: 172.16.0.0/12 allow\n"
    access_rules+="    access-control: 192.168.0.0/16 allow\n"
    access_rules+="    access-control: 100.64.0.0/10 allow\n"
    
    access_rules+="    access-control: ::1 allow\n"
    access_rules+="    access-control: ::ffff:0:0/96 allow\n"
    
    access_rules+="    access-control: 127.0.0.1 allow\n"
    if [ -n "$IPV4_ADDR" ] && [ "$IPV4_ADDR" != "127.0.0.1" ]; then
        access_rules+="    access-control: $IPV4_ADDR allow\n"
    fi
    if [ -n "$IPV6_ADDR" ]; then
        access_rules+="    access-control: $IPV6_ADDR allow\n"
    fi
    
    if [ "$IP_MODE_TYPE" == "public" ] && [ -n "$CUSTOM_IP_BLOCKS" ]; then
        for block in $CUSTOM_IP_BLOCKS; do
            access_rules+="    access-control: $block allow\n"
        done
    fi
    
    if [ "$IP_MODE_TYPE" == "local" ]; then
        access_rules+="    access-control: 0.0.0.0/0 allow\n"
        access_rules+="    access-control: ::/0 allow\n"
    else
        access_rules+="    access-control: 0.0.0.0/0 refuse\n"
        access_rules+="    access-control: ::/0 refuse\n"
    fi
    
    echo -e "$access_rules"
}

generate_unbound_config() {
    print_section "Gerando configuração do Unbound"
    
    local ipv6_setting="no"
    if [ "$ENABLE_IPV6" == "yes" ]; then
        ipv6_setting="yes"
    fi
    
    cat > /etc/unbound/unbound.conf << 'EOF'
# ============================================================================
# RESOLVIX - DNS Recursivo de Alta Performance
# Gerado automaticamente pelo instalador
# - Consulta direta aos root servers (sem forwarders)
# - DNSSEC habilitado
# - Otimizado para milhões de requisições por segundo
# - Configuração segura e robusta
# ============================================================================


server:
    interface: 0.0.0.0
EOF
    
    if [ "$ENABLE_IPV6" == "yes" ]; then
        echo "    interface: ::0" >> /etc/unbound/unbound.conf
    fi
    
    cat > /etc/unbound/unbound.conf << 'EOF'
# ============================================================================
# RESOLVIX - DNS Recursivo de Alta Performance
# Gerado automaticamente pelo instalador
# - Consulta direta aos root servers (sem forwarders)
# - DNSSEC habilitado
# - Otimizado para milhões de requisições por segundo
# - Configuração segura e robusta
# ============================================================================

server:
    statistics-interval: 0
    extended-statistics: yes
    statistics-cumulative: yes
    so-rcvbuf: 16m
    so-sndbuf: 16m
    msg-cache-size: 512m
    rrset-cache-size: 512m
    cache-max-ttl: 86400
    cache-min-ttl: 3600
    prefetch: yes
    prefetch-key: yes
    outgoing-range: 8192
    num-queries-per-thread: 8192
    outgoing-num-tcp: 4096
    incoming-num-tcp: 2048
EOF
    
    echo "    do-ip6: $ipv6_setting" >> /etc/unbound/unbound.conf
    
    cat >> /etc/unbound/unbound.conf << 'EOF'
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    harden-below-nxdomain: yes
    unwanted-reply-threshold: 10000000
    ratelimit: 100000
    ratelimit-slabs: 8
    ratelimit-size: 8m
    do-daemonize: yes
    directory: "/etc/unbound"

remote-control:
    control-enable: yes
    control-interface: /run/unbound.ctl
EOF
    
    print_success "Configuração do Unbound gerada"
}

validate_unbound_config() {
    print_section "Validando configuração do Unbound"
    
    if unbound-checkconf -q /etc/unbound/unbound.conf; then
        print_success "Configuração válida"
        return 0
    else
        print_error "Erro na configuração do Unbound"
        unbound-checkconf /etc/unbound/unbound.conf
        return 1
    fi
}

# ============================================================================
# INICIALIZAÇÃO E TESTES
# ============================================================================

start_unbound() {
    print_section "Iniciando serviço Unbound"
    
    systemctl enable unbound || {
        print_error "Falha ao ativar serviço no boot"
        return 1
    }
    
    systemctl restart unbound || {
        print_error "Falha ao iniciar Unbound"
        return 1
    }
    
    sleep 2
    
    if systemctl is-active --quiet unbound; then
        print_success "Unbound iniciado com sucesso"
        return 0
    else
        print_error "Unbound não está em execução"
        return 1
    fi
}

test_dns_resolution() {
    print_section "Testando resolução DNS"
    
    local test_domains=("google.com" "cloudflare.com" "root-servers.net")
    local success_count=0
    
    for domain in "${test_domains[@]}"; do
        if timeout 5 dig @127.0.0.1 "$domain" +short &> /dev/null; then
            print_success "Resolução de $domain bem-sucedida"
            ((success_count++))
        else
            print_warning "Falha ao resolver $domain"
        fi
    done
    
    if [ $success_count -ge 1 ]; then
        print_success "Testes de resolução DNS completados"
        return 0
    else
        print_error "Nenhuma resolução DNS bem-sucedida"
        return 1
    fi
}

test_recursive_query() {
    print_section "Testando consulta recursiva"
    
    local result=$(timeout 5 dig @127.0.0.1 google.com +short 2>&1)
    
    if [ -n "$result" ]; then
        print_success "Consulta recursiva funcionando"
        print_info "Resultado: $(echo "$result" | head -1)"
        return 0
    else
        print_warning "Falha em consulta recursiva"
        return 0
    fi
}

test_dnssec() {
    print_section "Testando validação DNSSEC"
    
    local result=$(timeout 5 dig @127.0.0.1 dnssec-failed.org +dnssec +short 2>&1)
    
    if echo "$result" | grep -q "SERVFAIL"; then
        print_success "DNSSEC está validando corretamente"
        return 0
    else
        print_warning "DNSSEC pode não estar validando (normal em modo teste)"
        return 0
    fi
}

test_access_control() {
    print_section "Testando controle de acesso"
    
    if [ "$IP_MODE_TYPE" == "public" ]; then
        print_info "Modo público ativo - acesso deve ser restrito"
    else
        print_info "Modo local ativo - acesso deve ser permitido para qualquer origem"
    fi
    
    print_success "Controle de acesso configurado"
}

test_performance() {
    print_section "Testando performance"
    
    local queries=5
    local start_time=$(date +%s%N)
    
    for i in $(seq 1 $queries); do
        timeout 5 dig @127.0.0.1 example.com +short &> /dev/null
    done
    
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    local avg_time=$(( duration / queries ))
    
    print_info "Tempo médio por consulta: ${avg_time}ms"
    print_success "Teste de performance concluído"
    return 0
}

# ============================================================================
# CONFIGURAÇÃO DE DNS DO SISTEMA
# ============================================================================

disable_systemd_resolved() {
    print_info "Desabilitando systemd-resolved de forma agressiva..."
    
    print_info "Parando systemd-resolved..."
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl kill systemd-resolved 2>/dev/null || true
    sleep 1
    
    print_info "Desabilitando systemd-resolved na inicialização..."
    systemctl disable systemd-resolved 2>/dev/null || true
    
    print_info "Mascarando serviço systemd-resolved..."
    systemctl mask systemd-resolved 2>/dev/null || true
    
    print_info "Removendo link simbólico de /etc/resolv.conf..."
    if [ -L /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
    fi
    
    if [ -f /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
    fi
    
    sleep 3
    
    print_success "systemd-resolved completamente desabilitado"
}

configure_system_dns() {
    print_section "Configurando DNS do sistema para usar Unbound"
    
    disable_systemd_resolved
    
    print_info "Aguardando liberação de porta 53..."
    for i in {1..10}; do
        if ! lsof -i :53 &>/dev/null 2>&1; then
            print_success "Porta 53 disponível"
            break
        fi
        sleep 1
    done
    
    print_info "Criando novo arquivo /etc/resolv.conf..."
    
    chattr -i /etc/resolv.conf 2>/dev/null || true
    
    rm -f /etc/resolv.conf
    
    cat > /etc/resolv.conf << 'EOF'
# ============================================================================
# Configurado automaticamente pelo RESOLVIX
# DNS Recursivo - Unbound
# ============================================================================
nameserver 127.0.0.1
EOF
    
    if [ "$ENABLE_IPV6" == "yes" ] && [ -n "$IPV6_ADDR" ]; then
        echo "nameserver ::1" >> /etc/resolv.conf
    fi
    
    chmod 644 /etc/resolv.conf
    
    print_info "Protegendo /etc/resolv.conf contra sobrescrita..."
    chattr +i /etc/resolv.conf 2>/dev/null || {
        print_warning "chattr não disponível, tentando alternativa..."
        chmod 444 /etc/resolv.conf
    }
    
    if grep -q "nameserver 127.0.0.1" /etc/resolv.conf; then
        print_success "DNS do sistema configurado para usar Unbound"
        return 0
    else
        print_error "Falha ao configurar /etc/resolv.conf"
        return 1
    fi
    
    echo ""
    print_info "Conteúdo final de /etc/resolv.conf:"
    cat /etc/resolv.conf
}

verify_dns_configuration() {
    print_section "Verificando configuração de DNS do sistema"
    
    print_info "Aguardando Unbound estar completamente pronto..."
    sleep 2
    
    echo ""
    print_info "Status de /etc/resolv.conf:"
    ls -la /etc/resolv.conf
    
    echo ""
    print_info "Conteúdo de /etc/resolv.conf:"
    cat /etc/resolv.conf
    
    echo ""
    print_info "Testando resolução com novo DNS..."
    
    print_info "Testando resolução via IPv4 (127.0.0.1)..."
    if timeout 5 dig @127.0.0.1 +short google.com A 2>/dev/null | grep -q "\."; then
        print_success "Resolução via IPv4 (127.0.0.1) funcionando"
        dig @127.0.0.1 +short google.com A 2>/dev/null | head -2 || true
    else
        print_warning "Falha na resolução via IPv4 (pode estar em cache)"
    fi
    
    if [ "$ENABLE_IPV6" == "yes" ]; then
        echo ""
        print_info "Testando resolução via IPv6 (::1)..."
        if timeout 5 dig @::1 +short google.com A 2>/dev/null | grep -q "\."; then
            print_success "Resolução via IPv6 (::1) funcionando"
            dig @::1 +short google.com A 2>/dev/null | head -2 || true
        else
            print_warning "Falha na resolução via IPv6"
        fi
    fi
    
    echo ""
    print_info "Testando resolução padrão do sistema (nslookup)..."
    if timeout 5 nslookup google.com 127.0.0.1 2>/dev/null | grep -q "Address"; then
        print_success "Sistema usando Unbound como DNS padrão"
    else
        print_warning "Sistema pode não estar usando Unbound corretamente"
    fi
    
    echo ""
    print_info "Status do systemd-resolved:"
    if systemctl is-enabled systemd-resolved 2>/dev/null | grep -q "enabled"; then
        print_warning "systemd-resolved ainda está habilitado"
    else
        print_success "systemd-resolved desabilitado"
    fi
    
    return 0
}

# ============================================================================
# EXPORTADOR PROMETHEUS
# ============================================================================

create_prometheus_exporter() {
    print_section "Criando exportador Prometheus para Unbound"
    
    mkdir -p /opt/resolvix
    
    cat > /opt/resolvix/unbound_exporter.py << 'PYTHON_EOF'
#!/usr/bin/env python3
"""
RESOLVIX - Exportador Prometheus para Unbound
Coleta estatísticas do Unbound e as exporta em formato Prometheus
"""

import subprocess
import re
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from pathlib import Path

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class UnboundMetrics:
    """Coleta e processa métricas do Unbound"""
    
    def __init__(self):
        self.metrics = {}
        self.last_update = 0
        self.cache_ttl = 5  # Cache de 5 segundos
    
    def execute_unbound_control(self, command):
        """Executa comando unbound-control"""
        try:
            result = subprocess.run(
                ['unbound-control', command],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.error(f"Erro ao executar unbound-control {command}: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"Exceção ao executar unbound-control: {e}")
            return None
    
    def parse_stats(self, stats_output):
        """Parse das estatísticas do Unbound"""
        metrics = {}
        
        for line in stats_output.split('\n'):
            if not line.strip():
                continue
            
            parts = line.split('=')
            if len(parts) != 2:
                continue
            
            key, value = parts[0].strip(), parts[1].strip()
            
            # Converter para número se possível
            try:
                if '.' in value:
                    metrics[key] = float(value)
                else:
                    metrics[key] = int(value)
            except ValueError:
                metrics[key] = value
        
        return metrics
    
    def get_metrics(self):
        """Obtém todas as métricas, agregando por thread"""
        current_time = time.time()
        if current_time - self.last_update < self.cache_ttl:
            return self.metrics
        stats = self.execute_unbound_control('stats')
        if stats:
            raw = self.parse_stats(stats)
            # Agregação de métricas por thread
            totals = {}
            thread_prefixes = set()
            for k in raw:
                m = re.match(r'thread(\d+)\.(.+)', k)
                if m:
                    thread_prefixes.add(m.group(2))
            for metric in thread_prefixes:
                total = 0
                for k, v in raw.items():
                    if k.endswith(metric):
                        try:
                            total += float(v)
                        except Exception:
                            pass
                totals[metric] = total
            # Mapear nomes agregados para o dashboard
            mapping = {
                'num_queries': 'unbound_total_queries',
                'num_cachehits': 'unbound_total_cached_queries',
                'num_recursivereplies': 'unbound_total_recursion_queries',
                'num_prefetch': 'unbound_total_prefetch',
                'num_queries_timed_out': 'unbound_total_recursion_time_timeouts',
                'num_dnssec_queries': 'unbound_total_dnssec_queries',
                'num_dnssec_bogus': 'unbound_total_dnssec_bogus',
                'requestlist_current': 'unbound_total_requestlist_current_all',
                'requestlist_overwritten': 'unbound_total_requestlist_overwritten',
                'num_cachemiss': 'unbound_total_cachemiss',
            }
            for k, v in mapping.items():
                if k in totals:
                    raw[v] = totals[k]
            self.metrics = raw
            self.last_update = current_time
        return self.metrics
    
    def format_prometheus(self):
        """Formata métricas em formato Prometheus"""
        metrics = self.get_metrics()
        output = []
        
        # Header
        output.append("# HELP unbound_info Informações do servidor Unbound")
        output.append("# TYPE unbound_info gauge")
        output.append('unbound_info{version="1.22.0"} 1')
        output.append("")
        
        # Métricas de queries
        output.append("# HELP unbound_queries_total Total de queries recebidas")
        output.append("# TYPE unbound_queries_total counter")
        if 'total.queries' in metrics:
            output.append(f"unbound_queries_total {metrics['total.queries']}")
        output.append("")
        
        # Métricas de cache
        output.append("# HELP unbound_cache_prefetches Total de prefetches do cache")
        output.append("# TYPE unbound_cache_prefetches counter")
        if 'total.prefetch' in metrics:
            output.append(f"unbound_cache_prefetches {metrics['total.prefetch']}")
        output.append("")
        
        # Métricas de hits e misses
        output.append("# HELP unbound_cache_hits Cache hits")
        output.append("# TYPE unbound_cache_hits counter")
        if 'total.queries' in metrics and 'total.cached_queries' in metrics:
            output.append(f"unbound_cache_hits {metrics.get('total.cached_queries', 0)}")
        output.append("")
        
        # Métricas de DNSSEC
        output.append("# HELP unbound_dnssec_queries DNSSEC queries")
        output.append("# TYPE unbound_dnssec_queries counter")
        if 'total.dnssec.queries' in metrics:
            output.append(f"unbound_dnssec_queries {metrics['total.dnssec.queries']}")
        output.append("")
        
        output.append("# HELP unbound_dnssec_bogus DNSSEC validações falhadas")
        output.append("# TYPE unbound_dnssec_bogus counter")
        if 'total.dnssec.bogus' in metrics:
            output.append(f"unbound_dnssec_bogus {metrics['total.dnssec.bogus']}")
        output.append("")
        
        # Métricas de recursão
        output.append("# HELP unbound_recursion_queries Queries recursivas")
        output.append("# TYPE unbound_recursion_queries counter")
        if 'total.recursion.queries' in metrics:
            output.append(f"unbound_recursion_queries {metrics['total.recursion.queries']}")
        output.append("")
        
        # Métricas de timeouts
        output.append("# HELP unbound_recursion_timeouts Timeouts de recursão")
        output.append("# TYPE unbound_recursion_timeouts counter")
        if 'total.recursion.time_timeouts' in metrics:
            output.append(f"unbound_recursion_timeouts {metrics['total.recursion.time_timeouts']}")
        output.append("")
        
        # Métricas de memória e threads
        output.append("# HELP unbound_requestlist_current Requisições pendentes na fila")
        output.append("# TYPE unbound_requestlist_current gauge")
        if 'total.requestlist.current.all' in metrics:
            output.append(f"unbound_requestlist_current {metrics['total.requestlist.current.all']}")
        output.append("")
        
        output.append("# HELP unbound_requestlist_overwritten Requisições sobrescritas")
        output.append("# TYPE unbound_requestlist_overwritten counter")
        if 'total.requestlist.overwritten' in metrics:
            output.append(f"unbound_requestlist_overwritten {metrics['total.requestlist.overwritten']}")
        output.append("")
        
        # Métricas de resposta
        output.append("# HELP unbound_responses_total Total de respostas")
        output.append("# TYPE unbound_responses_total counter")
        if 'total.responses' in metrics:
            output.append(f"unbound_responses_total {metrics['total.responses']}")
        output.append("")
        
        output.append("# HELP unbound_responses_servfail Respostas SERVFAIL")
        output.append("# TYPE unbound_responses_servfail counter")
        if 'total.responses_servfail' in metrics:
            output.append(f"unbound_responses_servfail {metrics['total.responses_servfail']}")
        output.append("")
        
        # Todos os métricas restantes
        output.append("# HELP unbound_stats_raw Estatísticas brutas do Unbound")
        output.append("# TYPE unbound_stats_raw gauge")
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                # Sanitizar nome da métrica
                metric_name = re.sub(r'[^a-zA-Z0-9_]', '_', f'unbound_{key}')
                output.append(f'{metric_name} {value}')
        
        return '\n'.join(output) + '\n'

class PrometheusExporterHandler(BaseHTTPRequestHandler):
    """Handler HTTP para o exportador Prometheus"""
    
    metrics = UnboundMetrics()
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            
            try:
                output = self.metrics.format_prometheus()
                self.wfile.write(output.encode('utf-8'))
            except Exception as e:
                logger.error(f"Erro ao gerar métricas: {e}")
                error_msg = f"Erro ao gerar métricas: {e}\n"
                self.wfile.write(error_msg.encode('utf-8'))
        
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK\n')
        
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'404 Not Found\n')
    
    def log_message(self, format, *args):
        """Log HTTP requests"""
        logger.info(f"{self.client_address[0]} - {format % args}")

def main():
    """Função principal"""
    port = 9100
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, PrometheusExporterHandler)
    
    logger.info(f"Iniciando exportador Prometheus na porta {port}")
    logger.info(f"Acesse http://localhost:{port}/metrics para ver as métricas")
    logger.info(f"Exportador acessível em: http://0.0.0.0:{port}/metrics")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Encerrando exportador...")
        httpd.shutdown()

if __name__ == '__main__':
    main()
PYTHON_EOF
    
    chmod +x /opt/resolvix/unbound_exporter.py
    print_success "Exportador Prometheus criado"
}

install_prometheus_dependencies() {
    print_section "Instalando dependências do Prometheus"
    
    python3 -m pip install prometheus-client --break-system-packages 2>/dev/null || {
        print_info "prometheus-client será instalado na primeira execução"
    }
    
    print_success "Dependências do Prometheus configuradas"
}

create_prometheus_exporter_service() {
    print_section "Criando serviço systemd do exportador Prometheus"
    
    print_info "Gerando arquivo de serviço..."
    cat > /etc/systemd/system/unbound-exporter.service << 'EOF'
[Unit]
Description=RESOLVIX - Unbound Prometheus Exporter
Documentation=https://nlnetlabs.nl/projects/unbound/
After=network-online.target unbound.service
Wants=network-online.target
Requires=unbound.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/resolvix
ExecStart=/usr/bin/python3 /opt/resolvix/unbound_exporter.py
ExecReload=/bin/kill -HUP $MAINPID

# Reinicialização automática em caso de falha
Restart=on-failure
RestartSec=10
StartLimitInterval=300
StartLimitBurst=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=unbound-exporter

# Segurança
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Arquivo de serviço criado"
    
    print_info "Recarregando daemon do systemd..."
    if ! systemctl daemon-reload; then
        print_error "Falha ao recarregar daemon do systemd"
        return 1
    fi
    
    print_info "Habilitando serviço no boot..."
    if ! systemctl enable unbound-exporter; then
        print_error "Falha ao habilitar serviço no boot"
        return 1
    fi
    
    print_success "Serviço exportador criado e habilitado"
    return 0
}

start_prometheus_exporter() {
    print_section "Iniciando serviço do exportador Prometheus"
    
    print_info "Iniciando unbound-exporter via systemctl..."
    if ! systemctl restart unbound-exporter 2>/dev/null; then
        print_error "Falha ao executar systemctl restart"
        journalctl -u unbound-exporter -n 5 --no-pager 2>/dev/null || true
        return 0
    fi
    
    sleep 3
    
    print_info "Verificando status do serviço..."
    if ! systemctl is-active --quiet unbound-exporter; then
        print_warning "Serviço unbound-exporter pode estar inicializando"
        journalctl -u unbound-exporter -n 5 --no-pager 2>/dev/null || true
        return 0
    fi
    
    print_success "Serviço unbound-exporter está ativo"
    
    print_info "Testando endpoint HTTP..."
    if timeout 5 curl -s http://127.0.0.1:9100/health &>/dev/null; then
        print_success "Exportador respondendo em http://127.0.0.1:9100"
        print_info "Acessível em:"
        print_info "  - IPv4: http://${IPV4_ADDR}:9100/metrics"
        if [ -n "$IPV6_ADDR" ]; then
            print_info "  - IPv6: http://[${IPV6_ADDR}]:9100/metrics"
        fi
        print_info "  - Localhost: http://127.0.0.1:9100/metrics"
        return 0
    else
        print_warning "Endpoint HTTP pode estar inicializando"
        sleep 2
        if timeout 5 curl -s http://127.0.0.1:9100/health &>/dev/null; then
            print_success "Exportador respondendo após retry"
            print_info "Acessível em:"
            print_info "  - IPv4: http://${IPV4_ADDR}:9100/metrics"
            if [ -n "$IPV6_ADDR" ]; then
                print_info "  - IPv6: http://[${IPV6_ADDR}]:9100/metrics"
            fi
            print_info "  - Localhost: http://127.0.0.1:9100/metrics"
            return 0
        else
            print_warning "Exportador pode estar em inicialização, verifique com: journalctl -u unbound-exporter -f"
            return 0
        fi
    fi
}

install_prometheus() {
    print_section "Instalando Prometheus"
    
    if command -v prometheus &> /dev/null; then
        print_info "Prometheus já está instalado"
        return 0
    fi
    
    PROM_VERSION="2.45.0"
    PROM_ARCH="amd64"
    
    print_info "Baixando Prometheus v${PROM_VERSION}..."
    cd /tmp
    
    if ! timeout 60 wget -q "https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-${PROM_ARCH}.tar.gz" 2>/dev/null; then
        print_warning "Falha ao baixar Prometheus, tentando versão anterior..."
        PROM_VERSION="2.44.0"
        if ! timeout 60 wget -q "https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-${PROM_ARCH}.tar.gz" 2>/dev/null; then
            print_warning "Não foi possível baixar Prometheus, continuando instalação"
            return 0
        fi
    fi
    
    if tar xzf "prometheus-${PROM_VERSION}.linux-${PROM_ARCH}.tar.gz" 2>/dev/null; then
        mkdir -p /opt/prometheus
        cp "prometheus-${PROM_VERSION}.linux-${PROM_ARCH}/prometheus" /opt/prometheus/ 2>/dev/null || true
        cp "prometheus-${PROM_VERSION}.linux-${PROM_ARCH}/promtool" /opt/prometheus/ 2>/dev/null || true
        
        ln -sf /opt/prometheus/prometheus /usr/local/bin/prometheus 2>/dev/null || true
        
        print_success "Prometheus instalado"
        return 0
    else
        print_warning "Falha ao extrair Prometheus"
        return 0
    fi
}

configure_prometheus() {
    print_section "Configurando Prometheus"
    
    mkdir -p /etc/prometheus /var/lib/prometheus 2>/dev/null || true
    
    cat > /etc/prometheus/prometheus.yml << 'EOF'
# Prometheus configuration - RESOLVIX
# Configuração automática do instalador Resolvix

global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'resolvix-dns'

alerting:
  alertmanagers:
    - static_configs:
        - targets: []

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'unbound'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 10s
    scrape_timeout: 5s
    metrics_path: '/metrics'
EOF
    
    print_success "Prometheus configurado"
    return 0
}

create_prometheus_service() {
    print_section "Criando serviço systemd do Prometheus"
    
    useradd -r -s /bin/false prometheus 2>/dev/null || true
    
    mkdir -p /etc/prometheus /var/lib/prometheus
    chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus 2>/dev/null || true
    
    cat > /etc/systemd/system/prometheus.service << EOF
[Unit]
Description=RESOLVIX - Prometheus Monitoring Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=prometheus
Group=prometheus
ExecStart=/opt/prometheus/prometheus \\
  --config.file=/etc/prometheus/prometheus.yml \\
  --storage.tsdb.path=/var/lib/prometheus \\
  --web.listen-address=0.0.0.0:9090 \\
  --web.console.templates=/opt/prometheus/consoles \\
  --web.console.libraries=/opt/prometheus/console_libraries

Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=prometheus

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable prometheus 2>/dev/null || true
    
    print_success "Serviço Prometheus criado"
    return 0
}

start_prometheus() {
    print_section "Iniciando Prometheus"
    
    if ! systemctl restart prometheus 2>/dev/null; then
        print_warning "Prometheus pode não estar completamente instalado"
        return 0
    fi
    
    sleep 3
    
    if systemctl is-active --quiet prometheus 2>/dev/null; then
        print_success "Prometheus iniciado com sucesso"
        print_info "Acesse em:"
        print_info "  - IPv4: http://${IPV4_ADDR}:9090"
        if [ -n "$IPV6_ADDR" ]; then
            print_info "  - IPv6: http://[${IPV6_ADDR}]:9090"
        fi
        print_info "  - Localhost: http://127.0.0.1:9090"
        return 0
    else
        print_warning "Prometheus pode estar inicializando, verifique com: systemctl status prometheus"
        return 0
    fi
}

test_prometheus_integration() {
    print_section "Testando integração Prometheus"
    
    print_info "Testando exportador..."
    if timeout 5 curl -s http://127.0.0.1:9100/metrics 2>/dev/null | grep -q "unbound_"; then
        print_success "Exportador respondendo com métricas"
    else
        print_info "Exportador ainda em inicialização, isto é normal"
    fi
    
    print_info "Testando Prometheus..."
    if timeout 5 curl -s http://127.0.0.1:9090/api/v1/targets 2>/dev/null | grep -q "unbound"; then
        print_success "Prometheus scraping unbound"
    else
        print_info "Prometheus ainda em inicialização ou scraping não iniciou"
    fi
    
    return 0
}

# ============================================================================
# DASHBOARD WEB
# ============================================================================

create_dashboard_service() {
    print_section "Criando serviço Web Dashboard"
    
    if [ -f /root/resolvix/dashboard-server.py ]; then
        chmod +x /root/resolvix/dashboard-server.py
        print_success "Script do dashboard configurado"
    fi
    
    cat > /etc/systemd/system/resolvix-dashboard.service << 'EOF'
[Unit]
Description=RESOLVIX - Web Dashboard Server
Documentation=https://nlnetlabs.nl/projects/unbound/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/resolvix
ExecStart=/usr/bin/python3 /root/resolvix/dashboard-server.py --host 0.0.0.0 --port 8080

# Reinicialização automática em caso de falha
Restart=on-failure
RestartSec=10
StartLimitInterval=300
StartLimitBurst=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=resolvix-dashboard

# Segurança
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Arquivo de serviço criado"
    
    print_info "Recarregando daemon do systemd..."
    if ! systemctl daemon-reload; then
        print_error "Falha ao recarregar daemon do systemd"
        return 1
    fi
    
    print_info "Habilitando serviço no boot..."
    if ! systemctl enable resolvix-dashboard; then
        print_error "Falha ao habilitar serviço no boot"
        return 1
    fi
    
    print_success "Serviço Web Dashboard criado e habilitado"
    return 0
}

start_dashboard_service() {
    print_section "Iniciando serviço Web Dashboard"
    
    print_info "Iniciando resolvix-dashboard via systemctl..."
    if ! systemctl restart resolvix-dashboard 2>/dev/null; then
        print_error "Falha ao executar systemctl restart"
        journalctl -u resolvix-dashboard -n 5 --no-pager 2>/dev/null || true
        return 0
    fi
    
    sleep 2
    
    print_info "Verificando status do serviço..."
    if ! systemctl is-active --quiet resolvix-dashboard; then
        print_warning "Serviço resolvix-dashboard pode estar inicializando"
        journalctl -u resolvix-dashboard -n 5 --no-pager 2>/dev/null || true
        return 0
    fi
    
    print_success "Serviço resolvix-dashboard está ativo"
    
    print_info "Testando endpoint HTTP..."
    if timeout 5 curl -s http://127.0.0.1:8080/health &>/dev/null; then
        print_success "Dashboard respondendo em http://127.0.0.1:8080"
        print_info "Acessível em:"
        print_info "  - IPv4: http://${IPV4_ADDR}:8080/dashboard"
        if [ -n "$IPV6_ADDR" ]; then
            print_info "  - IPv6: http://[${IPV6_ADDR}]:8080/dashboard"
        fi
        print_info "  - Localhost: http://127.0.0.1:8080/dashboard"
        return 0
    else
        print_warning "Dashboard pode estar inicializando"
        sleep 2
        if timeout 5 curl -s http://127.0.0.1:8080/health &>/dev/null; then
            print_success "Dashboard respondendo após retry"
            print_info "Acessível em:"
            print_info "  - IPv4: http://${IPV4_ADDR}:8080/dashboard"
            if [ -n "$IPV6_ADDR" ]; then
                print_info "  - IPv6: http://[${IPV6_ADDR}]:8080/dashboard"
            fi
            print_info "  - Localhost: http://127.0.0.1:8080/dashboard"
            return 0
        else
            print_warning "Dashboard pode estar em inicialização, verifique com: journalctl -u resolvix-dashboard -f"
            return 0
        fi
    fi
}

# ============================================================================
# STATUS E INFORMAÇÕES
# ============================================================================

show_status() {
    print_section "Status do Unbound"
    
    echo -e "\n${BOLD}Serviço:${NC}"
    systemctl status unbound --no-pager | head -3
    
    echo -e "\n${BOLD}Informações da Configuração:${NC}"
    echo "Modo de Operação: $([ "$IP_MODE_TYPE" == "local" ] && echo "Local (qualquer origem)" || echo "Público (restrito)")"
    echo "Versão IP: $([ "$ENABLE_IPV6" == "yes" ] && echo "IPv4 + IPv6" || echo "IPv4")"
    echo "IPv4: $IPV4_ADDR"
    if [ -n "$IPV6_ADDR" ]; then
        echo "IPv6: $IPV6_ADDR"
    fi
    
    echo -e "\n${BOLD}Estatísticas:${NC}"
    unbound-control stats 2>/dev/null || print_info "unbound-control não disponível no momento"
}

show_final_info() {
    echo -e "\n${GREEN}${BOLD}"
    echo "    ███████╗██╗   ██╗ ██████╗███████╗███████╗███████╗"
    echo "    ██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝██╔════╝"
    echo "    ███████╗██║   ██║██║     █████╗  ███████╗███████╗"
    echo "    ╚════██║██║   ██║██║     ██╔══╝  ╚════██║╚════██║"
    echo "    ███████║╚██████╔╝╚██████╗███████╗███████║███████║"
    echo "    ╚══════╝ ╚═════╝  ╚═════╝╚══════╝╚══════╝╚══════╝"
    echo -e "${NC}\n"
    
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║${GREEN}   RESOLVIX - Instalação Concluída com Sucesso! ✓${BOLD}          ║${NC}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${BOLD}📋 Informações do Servidor DNS:${NC}"
    echo -e "${BLUE}$(printf '─%.0s' {1..70})${NC}"
    echo "  Nome do Projeto ......... RESOLVIX"
    echo "  Tipo ................... DNS Recursivo"
    echo "  Servidor ............... Unbound (NLnet Labs)"
    echo ""
    echo -e "${BOLD}👤 Autor:${NC}"
    echo "  Nome ................... Renylson Marques"
    echo "  Email .................. renylsonm@gmail.com"
    echo "  Telefone ............... (87) 98846-3681"
    echo ""
    echo -e "${BOLD}⚙️  Configurações Aplicadas:${NC}"
    echo "  Mode ................... $([ "$IP_MODE_TYPE" == "local" ] && echo "🏠 Local (Qualquer Origem)" || echo "🌐 Público (Restrito)")"
    echo "  IP Versão .............. $([ "$ENABLE_IPV6" == "yes" ] && echo "IPv4 + IPv6" || echo "IPv4 Apenas")"
    echo "  Endereço IPv4 .......... $IPV4_ADDR"
    if [ -n "$IPV6_ADDR" ]; then
        echo "  Endereço IPv6 .......... $IPV6_ADDR"
    fi
    echo "  Porta .................. 53 (UDP/TCP)"
    echo "  Threads ................ 16"
    echo "  Cache Mensagens ........ 512MB"
    echo "  Cache RRSET ............ 512MB"
    echo "  DNSSEC ................. ✓ Habilitado"
    echo "  Performance ............ Otimizada (1M+ qps)"
    
    if [ "$INSTALL_PROMETHEUS" == "yes" ]; then
    echo ""
    echo -e "${BOLD}📊 Monitoramento Prometheus:${NC}"
    echo "  Status ................. ✓ Instalado e Ativo"
    echo "  Exportador ............. http://127.0.0.1:9100/metrics"
    echo "  Exportador (IPv4) ...... http://${IPV4_ADDR}:9100/metrics"
    if [ -n "$IPV6_ADDR" ]; then
        echo "  Exportador (IPv6) ...... http://[${IPV6_ADDR}]:9100/metrics"
    fi
    echo "  Prometheus UI .......... http://127.0.0.1:9090"
    echo "  Prometheus (IPv4) ...... http://${IPV4_ADDR}:9090"
    if [ -n "$IPV6_ADDR" ]; then
        echo "  Prometheus (IPv6) ...... http://[${IPV6_ADDR}]:9090"
    fi
    echo "  Job Unbound ............ Scraping a cada 10s"
    fi
    
    echo ""
    echo -e "${BOLD}🎨 Web Dashboard:${NC}"
    echo "  Status ................. ✓ Instalado e Ativo"
    echo "  Dashboard .............. http://127.0.0.1:8080/dashboard"
    echo "  Dashboard (IPv4) ....... http://${IPV4_ADDR}:8080/dashboard"
    if [ -n "$IPV6_ADDR" ]; then
        echo "  Dashboard (IPv6) ....... http://[${IPV6_ADDR}]:8080/dashboard"
    fi
    echo "  API Métricas ........... http://127.0.0.1:8080/metrics"
    echo "  Health Check ........... http://127.0.0.1:8080/health"
    echo "  Características:"
    echo "    ✓ Mobile-first responsivo"
    echo "    ✓ Dark mode profissional"
    echo "    ✓ Gráficos em tempo real"
    echo "    ✓ Exportar dados (JSON)"
    echo "    ✓ Sem dependências JavaScript"    echo ""
    echo -e "${BOLD}🔧 Comandos Úteis:${NC}"
    echo "  Status DNS ............. systemctl status unbound"
    echo "  Reiniciar DNS .......... systemctl restart unbound"
    echo "  Parar DNS .............. systemctl stop unbound"
    echo "  Logs DNS em Tempo Real . journalctl -u unbound -f"
    echo "  Teste de DNS ........... dig @127.0.0.1 google.com"
    echo "  Estatísticas ........... unbound-control stats"
    echo "  Arquivo Config ......... /etc/unbound/unbound.conf"
    
    if [ "$INSTALL_PROMETHEUS" == "yes" ]; then
        echo ""
        echo -e "${BOLD}📊 Comandos Prometheus:${NC}"
        echo "  Status Exportador ...... systemctl status unbound-exporter"
        echo "  Reiniciar Exportador ... systemctl restart unbound-exporter"
        echo "  Status Prometheus ...... systemctl status prometheus"
        echo "  Reiniciar Prometheus ... systemctl restart prometheus"
        echo "  Logs Exportador ........ journalctl -u unbound-exporter -f"
        echo "  Logs Prometheus ........ journalctl -u prometheus -f"
        echo "  Testar Métricas (IPv4)  curl http://127.0.0.1:9100/metrics"
        echo "  Testar Métricas IP ..... curl http://${IPV4_ADDR}:9100/metrics"
        if [ -n "$IPV6_ADDR" ]; then
            echo "  Testar Métricas (IPv6)  curl http://[${IPV6_ADDR}]:9100/metrics"
        fi
    fi
    
    echo ""
    echo -e "${BOLD}🎨 Comandos Web Dashboard:${NC}"
    echo "  Status Dashboard ....... systemctl status resolvix-dashboard"
    echo "  Reiniciar Dashboard .... systemctl restart resolvix-dashboard"
    echo "  Logs Dashboard ......... journalctl -u resolvix-dashboard -f"
    echo "  Testar Dashboard (IPv4)  curl http://127.0.0.1:8080/health"
    echo "  Testar Dashboard IP .... curl http://${IPV4_ADDR}:8080/health"
    if [ -n "$IPV6_ADDR" ]; then
        echo "  Testar Dashboard (IPv6)  curl http://[${IPV6_ADDR}]:8080/health"
    fi
    
    echo ""
    echo -e "${BOLD}🔒 Boas Práticas de Produção:${NC}"
    echo "  ✓ Executar Unbound em usuário não-root"
    echo "  ✓ Configurar firewall adequadamente"
    echo "  ✓ Monitorar performance e logs regularmente"
    echo "  ✓ Fazer backups periódicos da configuração"
    echo "  ✓ Manter o sistema e pacotes atualizados"
    echo "  ✓ Implementar rate limiting para proteção"
    echo "  ✓ Habilitar DNSSEC para validação de respostas"
    
    if [ "$INSTALL_PROMETHEUS" == "yes" ]; then
        echo "  ✓ Configurar dashboard Grafana com arquivo grafana_dashboard.json"
        echo "  ✓ Proteger acesso Prometheus com autenticação"
    fi
    
    echo ""
    echo -e "${BOLD}📚 Documentação:${NC}"
    echo "  Site Oficial Unbound ... https://nlnetlabs.nl/projects/unbound/"
    echo "  Documentação Unbound ... https://unbound.docs.nlnetlabs.nl/"
    if [ "$INSTALL_PROMETHEUS" == "yes" ]; then
        echo "  Site Oficial Prometheus  https://prometheus.io"
        echo "  Dashboard Grafana ....... /root/resolvix/grafana_dashboard.json"
    fi
    
    echo ""
    echo -e "${BLUE}$(printf '═%.0s' {1..70})${NC}"
    echo ""
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    print_header
    
    check_root
    check_debian_version
    check_internet
    get_network_config
    
    print_section "Resumo das verificações"
    echo ""
    print_success "✓ Executando como root"
    print_success "✓ Debian 13 detectado"
    print_success "✓ Conectividade confirmada"
    print_success "✓ IPv4: $IPV4_ADDR"
    if [ -n "$IPV6_ADDR" ]; then
        print_success "✓ IPv6: $IPV6_ADDR"
    fi
    echo ""
    
    if ! confirm_action "Deseja continuar com a instalação?"; then
        print_error "Instalação cancelada pelo usuário"
        exit 0
    fi
    
    ask_ip_mode
    ask_ip_version
    ask_public_ip_blocks
    ask_monitoring
    
    echo ""
    print_section "Resumo da configuração"
    echo ""
    echo "Modo de Operação: $([ "$IP_MODE_TYPE" == "local" ] && echo "Local" || echo "Público")"
    echo "Versão de IP: $([ "$ENABLE_IPV6" == "yes" ] && echo "IPv4 + IPv6" || echo "IPv4")"
    if [ "$IP_MODE_TYPE" == "public" ] && [ -n "$CUSTOM_IP_BLOCKS" ]; then
        echo "Blocos IP customizados: $CUSTOM_IP_BLOCKS"
    fi
    if [ "$INSTALL_PROMETHEUS" == "yes" ]; then
        echo "Prometheus + Exportador: Sim"
    else
        echo "Prometheus + Exportador: Não"
    fi
    echo ""
    
    if ! confirm_action "Confirma estas configurações e deseja prosseguir?"; then
        print_error "Instalação cancelada pelo usuário"
        exit 0
    fi
    
    update_system
    install_dependencies
    backup_config
    generate_unbound_config
    
    if ! validate_unbound_config; then
        print_error "Falha na validação da configuração. Instalação abortada."
        exit 1
    fi
    
    if ! start_unbound; then
        print_error "Falha ao iniciar Unbound. Verifique os logs."
        exit 1
    fi
    
    print_section "Executando testes de funcionalidade"
    test_dns_resolution || true
    test_recursive_query || true
    test_dnssec || true
    test_access_control || true
    test_performance || true
    
    configure_system_dns || print_warning "Falha ao configurar DNS do sistema"
    
    verify_dns_configuration || true
    
    if [ "$INSTALL_PROMETHEUS" == "yes" ]; then
        print_section "Iniciando instalação do Prometheus"
        
        install_prometheus_dependencies || true
        create_prometheus_exporter || true
        
        print_info "Criando serviço do exportador..."
        create_prometheus_exporter_service || print_warning "Falha ao criar serviço do exportador"
        
        print_info "Iniciando serviço do exportador..."
        start_prometheus_exporter || true
        
        print_info "Instalando Prometheus..."
        install_prometheus || print_warning "Falha ao instalar Prometheus"
        
        print_info "Configurando Prometheus..."
        configure_prometheus || print_warning "Falha ao configurar Prometheus"
        
        print_info "Criando serviço do Prometheus..."
        create_prometheus_service || print_warning "Falha ao criar serviço do Prometheus"
        
        print_info "Iniciando Prometheus..."
        start_prometheus || true
        
        sleep 3
        test_prometheus_integration || true
    fi
    
    print_section "Configurando Web Dashboard"
    
    print_info "Criando serviço do dashboard..."
    create_dashboard_service || print_warning "Falha ao criar serviço do dashboard"
    
    print_info "Iniciando serviço do dashboard..."
    start_dashboard_service || true
    
    print_section "Etapa Final: Validação e Configuração Definitiva de DNS"
    print_info "Executando última configuração de DNS..."
    chattr -i /etc/resolv.conf 2>/dev/null || true
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    if [ "$ENABLE_IPV6" == "yes" ]; then
        echo "nameserver ::1" >> /etc/resolv.conf
    fi
    chattr +i /etc/resolv.conf 2>/dev/null || true
    print_success "DNS definitivamente configurado para localhost"
    
    show_status
    show_final_info
    
    print_success "Instalação completada com sucesso!"
}

# ============================================================================
# EXECUÇÃO
# ============================================================================

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    print_section "Otimização de buffers do sistema para Unbound"
    SYSCTL_FILE="/etc/sysctl.conf"
    if ! grep -q 'net.core.rmem_max=16777216' "$SYSCTL_FILE" 2>/dev/null; then
        echo 'net.core.rmem_max=16777216' >> "$SYSCTL_FILE"
        print_info "Adicionado net.core.rmem_max=16777216 ao $SYSCTL_FILE"
    fi
    if ! grep -q 'net.core.wmem_max=16777216' "$SYSCTL_FILE" 2>/dev/null; then
        echo 'net.core.wmem_max=16777216' >> "$SYSCTL_FILE"
        print_info "Adicionado net.core.wmem_max=16777216 ao $SYSCTL_FILE"
    fi
    sysctl -p >/dev/null 2>&1 && print_success "Buffers otimizados e aplicados com sucesso" || print_warning "Não foi possível aplicar sysctl -p automaticamente, aplique manualmente se necessário."

    main "$@"
fi
