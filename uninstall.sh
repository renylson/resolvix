#!/bin/bash

################################################################################
#                      RESOLVIX - SCRIPT DE DESINSTALAÇÃO                      #
#                                                                              #
#           Este script remove completamente a instalação do RESOLVIX          #
#                                                                              #
################################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

print_header() {
    echo -e "\n${RED}${BOLD}"
    echo "    ╔═══════════════════════════════════════════════════════════╗"
    echo "    ║         RESOLVIX - SCRIPT DE DESINSTALAÇÃO               ║"
    echo "    ║              ⚠️  OPERAÇÃO IRREVERSÍVEL  ⚠️              ║"
    echo "    ╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Este script deve ser executado como root!"
        exit 1
    fi
    print_success "Executando como root"
}

confirm_uninstall() {
    echo -e "${RED}${BOLD}⚠️  AVISO: Esta ação irá:${NC}"
    echo "  • Parar todos os serviços (Unbound, Prometheus, Exportador)"
    echo "  • Remover configurações"
    echo "  • Remover dados acumulados"
    echo "  • Remover binários instalados"
    echo ""
    echo -e "Esta operação ${RED}NÃO pode ser desfeita${NC} sem backup!"
    echo ""
    
    read -p "$(echo -e ${RED}${BOLD}Digite 'DESINSTALAR' para confirmar: ${NC})" confirmation
    
    if [ "$confirmation" != "DESINSTALAR" ]; then
        print_error "Desinstalação cancelada"
        exit 0
    fi
}

stop_services() {
    echo -e "\n${BLUE}${BOLD}▶ Parando serviços...${NC}"
    
    systemctl stop unbound 2>/dev/null || print_warning "Unbound não estava rodando"
    systemctl stop prometheus 2>/dev/null || print_warning "Prometheus não estava rodando"
    systemctl stop unbound-exporter 2>/dev/null || print_warning "Exportador não estava rodando"
    
    print_success "Serviços parados"
}

disable_services() {
    echo -e "\n${BLUE}${BOLD}▶ Desabilitando serviços...${NC}"
    
    systemctl disable unbound 2>/dev/null || true
    systemctl disable prometheus 2>/dev/null || true
    systemctl disable unbound-exporter 2>/dev/null || true
    
    print_success "Serviços desabilitados"
}

remove_systemd_files() {
    echo -e "\n${BLUE}${BOLD}▶ Removendo arquivos systemd...${NC}"
    
    rm -f /etc/systemd/system/unbound-exporter.service
    rm -f /etc/systemd/system/prometheus.service
    
    systemctl daemon-reload
    
    print_success "Arquivos systemd removidos"
}

remove_packages() {
    echo -e "\n${BLUE}${BOLD}▶ Removendo pacotes...${NC}"
    
    apt-get remove -y unbound unbound-anchor 2>/dev/null || true
    
    print_success "Pacotes removidos"
}

remove_directories() {
    echo -e "\n${BLUE}${BOLD}▶ Removendo diretórios...${NC}"
    
    rm -rf /opt/resolvix
    rm -rf /opt/prometheus
    rm -rf /etc/prometheus
    rm -rf /var/lib/prometheus
    
    print_success "Diretórios removidos"
}

restore_dns() {
    echo -e "\n${BLUE}${BOLD}▶ Restaurando DNS do sistema...${NC}"
    
    chattr -i /etc/resolv.conf 2>/dev/null || true
    
    rm -f /etc/resolv.conf
    
    systemctl unmask systemd-resolved 2>/dev/null || true
    systemctl enable systemd-resolved 2>/dev/null || true
    systemctl start systemd-resolved 2>/dev/null || true
    
    print_success "DNS restaurado"
}

show_summary() {
    echo -e "\n${GREEN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║      RESOLVIX - Desinstalação Completada com Sucesso!     ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
    
    echo -e "${BOLD}O que foi removido:${NC}"
    echo "  ✓ Serviços systemd (unbound, prometheus, exportador)"
    echo "  ✓ Pacotes (unbound, unbound-anchor)"
    echo "  ✓ Diretórios de configuração"
    echo "  ✓ Dados acumulados"
    echo "  ✓ Binários instalados"
    echo ""
    
    echo -e "${BOLD}Próximas ações recomendadas:${NC}"
    echo "  • Verificar DNS do sistema: nslookup google.com"
    echo "  • Limpar cache: systemctl restart systemd-resolved"
    echo "  • Remover repositório: rm -rf /root/resolvix (opcional)"
    echo ""
}

main() {
    print_header
    check_root
    
    print_warning "Você está prestes a desinstalar o RESOLVIX completamente!"
    echo ""
    
    confirm_uninstall
    
    stop_services
    disable_services
    remove_systemd_files
    remove_packages
    remove_directories
    restore_dns
    
    show_summary
    
    print_success "Desinstalação finalizada"
}

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
