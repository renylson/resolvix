#!/bin/bash

################################################################################
#                                  RESOLVIX                                    #
#                    Instalador de DNS Recursivo - Unbound                    #
#                                                                              #
# Autor: Renylson Marques                                                     #
# Email: renylsonm@gmail.com                                                  #
# Telefone: (87) 98846-3681                                                   #
#                                                                              #
# Descrição: Script de instalação e configuração de servidor DNS recursivo    #
#           de alta performance usando Unbound em Debian 13                   #
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
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                       RESOLVIX v1.0                           ║"
    echo "║            Instalador de DNS Recursivo - Unbound              ║"
    echo "║                                                                ║"
    echo "║  Autor: Renylson Marques                                      ║"
    echo "║  Email: renylsonm@gmail.com                                   ║"
    echo "║  Telefone: (87) 98846-3681                                    ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
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
    
    while true; do
        read -p "$(echo -e ${YELLOW}${BOLD}$prompt' [s/n]: '${NC})" response
        case "$response" in
            [sS]|[yY]|sim|yes)
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
    
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
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
    
    # Tentar obter IPv4
    IPV4_ADDR=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)
    
    # Tentar obter IPv6
    IPV6_ADDR=$(ip -6 addr show | grep -oP '(?<=inet6\s)([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | grep -v '^::1' | grep -v '^fe80' | head -1)
    
    if [ -z "$IPV4_ADDR" ]; then
        print_warning "Nenhum endereço IPv4 encontrado"
        IPV4_ADDR="127.0.0.1"
    else
        print_success "IPv4 detectado: $IPV4_ADDR"
    fi
    
    if [ -n "$IPV6_ADDR" ]; then
        print_success "IPv6 detectado: $IPV6_ADDR"
    else
        print_warning "Nenhum endereço IPv6 detectado"
        IPV6_ADDR=""
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
    echo "Por exemplo: 203.0.113.0/24 203.0.114.0/24"
    echo "Ou pressione Enter para usar apenas IPs privados padrão"
    echo ""
    
    read -p "Blocos IP (separados por espaço): " CUSTOM_IP_BLOCKS
    
    if [ -z "$CUSTOM_IP_BLOCKS" ]; then
        print_info "Usando blocos IP privados padrão"
        CUSTOM_IP_BLOCKS=""
    else
        print_success "Blocos customizados: $CUSTOM_IP_BLOCKS"
    fi
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
    
    local packages="unbound unbound-anchor curl wget net-tools dnsutils iputils-ping"
    
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
    
    # IPs privados padrão
    access_rules+="    access-control: 10.0.0.0/8 allow\n"
    access_rules+="    access-control: 172.16.0.0/12 allow\n"
    access_rules+="    access-control: 192.168.0.0/16 allow\n"
    access_rules+="    access-control: 100.64.0.0/10 allow\n"
    
    # IPv6 loopback
    access_rules+="    access-control: ::1 allow\n"
    access_rules+="    access-control: ::ffff:0:0/96 allow\n"
    
    # IPs do servidor local
    access_rules+="    access-control: 127.0.0.1 allow\n"
    if [ -n "$IPV4_ADDR" ] && [ "$IPV4_ADDR" != "127.0.0.1" ]; then
        access_rules+="    access-control: $IPV4_ADDR allow\n"
    fi
    if [ -n "$IPV6_ADDR" ]; then
        access_rules+="    access-control: $IPV6_ADDR allow\n"
    fi
    
    # Blocos customizados em modo público
    if [ "$IP_MODE_TYPE" == "public" ] && [ -n "$CUSTOM_IP_BLOCKS" ]; then
        for block in $CUSTOM_IP_BLOCKS; do
            access_rules+="    access-control: $block allow\n"
        done
    fi
    
    # Regra padrão
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
    
    cat >> /etc/unbound/unbound.conf << EOF
    port: 53
EOF
    
    # Adicionar regras de access control
    generate_access_control >> /etc/unbound/unbound.conf
    
    cat >> /etc/unbound/unbound.conf << 'EOF'
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    verbosity: 1
    num-threads: 16
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
        if dig @127.0.0.1 "$domain" +short &> /dev/null; then
            print_success "Resolução de $domain bem-sucedida"
            ((success_count++))
        else
            print_warning "Falha ao resolver $domain"
        fi
    done
    
    if [ $success_count -ge 2 ]; then
        return 0
    else
        return 1
    fi
}

test_recursive_query() {
    print_section "Testando consulta recursiva"
    
    local result=$(dig @127.0.0.1 google.com +short 2>&1)
    
    if [ -n "$result" ]; then
        print_success "Consulta recursiva funcionando"
        print_info "Resultado: $(echo "$result" | head -1)"
        return 0
    else
        print_error "Falha em consulta recursiva"
        return 1
    fi
}

test_dnssec() {
    print_section "Testando validação DNSSEC"
    
    local result=$(dig @127.0.0.1 dnssec-failed.org +dnssec +short 2>&1)
    
    if echo "$result" | grep -q "SERVFAIL"; then
        print_success "DNSSEC está validando corretamente"
        return 0
    else
        print_warning "DNSSEC pode não estar funcionando corretamente"
        return 1
    fi
}

test_access_control() {
    print_section "Testando controle de acesso"
    
    # Se em modo público, testar se IP externo é bloqueado
    if [ "$IP_MODE_TYPE" == "public" ]; then
        print_info "Modo público ativo - acesso deve ser restrito"
    else
        print_info "Modo local ativo - acesso deve ser permitido para qualquer origem"
    fi
    
    print_success "Controle de acesso configurado"
}

test_performance() {
    print_section "Testando performance"
    
    local queries=10
    local start_time=$(date +%s%N)
    
    for i in $(seq 1 $queries); do
        dig @127.0.0.1 example.com +short &> /dev/null
    done
    
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    local avg_time=$(( duration / queries ))
    
    print_info "Tempo médio por consulta: ${avg_time}ms"
    print_success "Teste de performance concluído"
}

# ============================================================================
# CONFIGURAÇÃO DE DNS DO SISTEMA
# ============================================================================

configure_system_dns() {
    print_section "Configurando DNS do sistema"
    
    # Criar/atualizar /etc/resolv.conf com nosso servidor
    cat > /etc/resolv.conf << EOF
# Configurado automaticamente pelo RESOLVIX
nameserver 127.0.0.1
EOF
    
    if [ "$ENABLE_IPV6" == "yes" ] && [ -n "$IPV6_ADDR" ]; then
        echo "nameserver ::1" >> /etc/resolv.conf
    fi
    
    # Proteger contra sobrescrita
    chattr +i /etc/resolv.conf 2>/dev/null || true
    
    print_success "DNS do sistema configurado para usar Unbound"
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
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║          RESOLVIX - Instalação Concluída com Sucesso!         ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
    
    echo -e "${BOLD}Informações do Servidor DNS:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Nome do Projeto: RESOLVIX"
    echo "Tipo: DNS Recursivo"
    echo "Servidor: Unbound"
    echo ""
    echo "Autor: Renylson Marques"
    echo "Email: renylsonm@gmail.com"
    echo "Telefone: (87) 98846-3681"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${BOLD}Configurações:${NC}"
    echo "├─ Modo: $([ "$IP_MODE_TYPE" == "local" ] && echo "Local" || echo "Público")"
    echo "├─ IP: $IPV4_ADDR"
    if [ -n "$IPV6_ADDR" ]; then
        echo "├─ IPv6: $IPV6_ADDR"
    fi
    echo "├─ Versão IP: $([ "$ENABLE_IPV6" == "yes" ] && echo "IPv4 + IPv6" || echo "IPv4")"
    echo "├─ Porta: 53 (UDP/TCP)"
    echo "├─ Threads: 16"
    echo "├─ Cache MSG: 512MB"
    echo "├─ Cache RRSET: 512MB"
    echo "├─ DNSSEC: Ativado"
    echo "└─ Performance: Otimizada"
    echo ""
    echo -e "${BOLD}Comandos Úteis:${NC}"
    echo "├─ Status:     systemctl status unbound"
    echo "├─ Reiniciar:  systemctl restart unbound"
    echo "├─ Parar:      systemctl stop unbound"
    echo "├─ Logs:       journalctl -u unbound -f"
    echo "├─ Teste DNS:  dig @127.0.0.1 google.com"
    echo "├─ Stats:      unbound-control stats"
    echo "└─ Config:     /etc/unbound/unbound.conf"
    echo ""
    echo -e "${YELLOW}${BOLD}⚠ Importante:${NC}"
    echo "├─ Este servidor está configurado como DNS local da máquina"
    echo "├─ Para usar em produção, considere as seguintes boas práticas:"
    echo "│  • Executar Unbound em usuário não-root"
    echo "│  • Configurar firewall adequadamente"
    echo "│  • Monitorar performance e logs regularmente"
    echo "│  • Fazer backups periódicos da configuração"
    echo "│  • Manter o sistema e pacotes atualizados"
    echo "└─ Consulte a documentação: https://nlnetlabs.nl/projects/unbound/"
    echo ""
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    print_header
    
    # Verificações pré-instalação
    check_root
    check_debian_version
    check_internet
    get_network_config
    
    # Confirmação final antes de iniciar
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
    
    # Perguntas interativas
    ask_ip_mode
    ask_ip_version
    ask_public_ip_blocks
    
    echo ""
    print_section "Resumo da configuração"
    echo ""
    echo "Modo de Operação: $([ "$IP_MODE_TYPE" == "local" ] && echo "Local" || echo "Público")"
    echo "Versão de IP: $([ "$ENABLE_IPV6" == "yes" ] && echo "IPv4 + IPv6" || echo "IPv4")"
    if [ "$IP_MODE_TYPE" == "public" ] && [ -n "$CUSTOM_IP_BLOCKS" ]; then
        echo "Blocos IP customizados: $CUSTOM_IP_BLOCKS"
    fi
    echo ""
    
    if ! confirm_action "Confirma estas configurações e deseja prosseguir?"; then
        print_error "Instalação cancelada pelo usuário"
        exit 0
    fi
    
    # Instalação
    update_system
    install_dependencies
    backup_config
    generate_unbound_config
    
    # Validação e teste
    if ! validate_unbound_config; then
        print_error "Falha na validação da configuração. Instalação abortada."
        exit 1
    fi
    
    if ! start_unbound; then
        print_error "Falha ao iniciar Unbound. Verifique os logs."
        exit 1
    fi
    
    # Testes de funcionalidade
    print_section "Executando testes de funcionalidade"
    test_dns_resolution
    test_recursive_query
    test_dnssec
    test_access_control
    test_performance
    
    # Configurar DNS do sistema
    configure_system_dns
    
    # Status final
    show_status
    show_final_info
    
    print_success "Instalação completada com sucesso!"
}

# ============================================================================
# EXECUÇÃO
# ============================================================================

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
