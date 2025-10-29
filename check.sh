#!/bin/bash

# RESOLVIX - Script de Teste Rápido
# Verifica o status de todos os serviços

echo -e "\n\033[1;36m╔════════════════════════════════════════════════════════════════╗\033[0m"
echo -e "\033[1;36m║            RESOLVIX - Verificação de Saúde do Sistema          ║\033[0m"
echo -e "\033[1;36m╚════════════════════════════════════════════════════════════════╝\033[0m\n"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_service() {
    local service=$1
    local port=$2
    
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}✓${NC} $service: Ativo"
        if [ -n "$port" ]; then
            if netstat -tuln 2>/dev/null | grep -q ":$port "; then
                echo -e "  ${GREEN}→ Porta $port: Respondendo${NC}"
            else
                echo -e "  ${YELLOW}⚠ Porta $port: Não respondendo${NC}"
            fi
        fi
        return 0
    else
        echo -e "${RED}✗${NC} $service: Inativo"
        return 1
    fi
}

echo -e "\033[1;33m📋 STATUS DOS SERVIÇOS:\033[0m"
echo "───────────────────────────────────────────────────────────────"

check_service "unbound" "53"
check_service "unbound-exporter" "9100"
check_service "prometheus" "9090"

echo ""
echo -e "\033[1;33m🔍 TESTES DE CONECTIVIDADE:\033[0m"
echo "───────────────────────────────────────────────────────────────"

# Teste DNS
if timeout 2 dig @127.0.0.1 google.com +short &>/dev/null; then
    echo -e "${GREEN}✓${NC} DNS (dig @127.0.0.1): Funcionando"
else
    echo -e "${RED}✗${NC} DNS (dig @127.0.0.1): Falhando"
fi

# Teste nslookup
if timeout 2 nslookup google.com 127.0.0.1 &>/dev/null; then
    echo -e "${GREEN}✓${NC} nslookup: Funcionando"
else
    echo -e "${RED}✗${NC} nslookup: Falhando"
fi

# Teste exportador
if timeout 2 curl -s http://127.0.0.1:9100/health &>/dev/null; then
    echo -e "${GREEN}✓${NC} Exportador Prometheus: Respondendo"
else
    echo -e "${RED}✗${NC} Exportador Prometheus: Não respondendo"
fi

# Teste Prometheus
if timeout 2 curl -s http://127.0.0.1:9090/-/healthy &>/dev/null; then
    echo -e "${GREEN}✓${NC} Prometheus: Respondendo"
else
    echo -e "${RED}✗${NC} Prometheus: Não respondendo"
fi

echo ""
echo -e "\033[1;33m📊 ESTATÍSTICAS UNBOUND:\033[0m"
echo "───────────────────────────────────────────────────────────────"

if command -v unbound-control &>/dev/null; then
    stats=$(unbound-control stats 2>/dev/null)
    if [ -n "$stats" ]; then
        queries=$(echo "$stats" | grep "total.queries=" | cut -d= -f2)
        cached=$(echo "$stats" | grep "total.queries.cache" | head -1 | cut -d= -f2)
        recursion=$(echo "$stats" | grep "total.recursion.queries=" | cut -d= -f2)
        
        echo -e "Total de Queries:      ${GREEN}$queries${NC}"
        echo -e "Queries do Cache:      ${GREEN}$cached${NC}"
        echo -e "Queries Recursivas:    ${GREEN}$recursion${NC}"
    else
        echo -e "${YELLOW}⚠ Não foi possível obter estatísticas${NC}"
    fi
else
    echo -e "${YELLOW}⚠ unbound-control não disponível${NC}"
fi

echo ""
echo -e "\033[1;33m🔗 ACESSOS:\033[0m"
echo "───────────────────────────────────────────────────────────────"
echo "Prometheus UI:        http://127.0.0.1:9090"
echo "Métricas Unbound:     http://127.0.0.1:9100/metrics"
echo "Saúde Exportador:     http://127.0.0.1:9100/health"

echo ""
echo -e "\033[1;33m📚 COMANDOS ÚTEIS:\033[0m"
echo "───────────────────────────────────────────────────────────────"
echo "systemctl status unbound                    # Ver status Unbound"
echo "journalctl -u unbound -f                    # Logs em tempo real"
echo "dig @127.0.0.1 google.com                   # Testar DNS"
echo "unbound-control stats                       # Estatísticas"
echo ""
