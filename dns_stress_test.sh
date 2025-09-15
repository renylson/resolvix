#!/bin/bash

# DNS Stress Test Script
# Script para teste de estresse em servidor DNS com múltiplas consultas paralelas
# Autor: Sistema Resolvix
# Data: $(date)

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurações padrão
DNS_SERVER="127.0.0.1"
PORT="53"
CONCURRENT_QUERIES=100
TOTAL_QUERIES=1000
TIMEOUT=5
QUERY_TYPE="A"
OUTPUT_FILE="/tmp/dns_stress_$(date +%Y%m%d_%H%M%S).log"

# Lista de domínios para teste (mix de domínios populares e aleatórios)
DOMAINS=(
    "google.com"
    "youtube.com"
    "facebook.com"
    "amazon.com"
    "wikipedia.org"
    "twitter.com"
    "instagram.com"
    "linkedin.com"
    "github.com"
    "stackoverflow.com"
    "reddit.com"
    "netflix.com"
    "microsoft.com"
    "apple.com"
    "cloudflare.com"
    "example.com"
    "test.com"
    "random1.test"
    "random2.test"
    "random3.test"
    "nonexistent.domain"
    "invalid.tld"
    "cnn.com"
    "bbc.com"
    "yahoo.com"
    "bing.com"
    "gmail.com"
    "dropbox.com"
    "adobe.com"
    "ubuntu.com"
    "debian.org"
    "centos.org"
    "redhat.com"
    "mozilla.org"
    "chrome.com"
    "firefox.com"
    "opera.com"
    "whatsapp.com"
    "telegram.org"
    "discord.com"
    "slack.com"
    "zoom.us"
    "skype.com"
    "twitch.tv"
    "tiktok.com"
    "snapchat.com"
    "pinterest.com"
    "tumblr.com"
    "wordpress.com"
    "blogger.com"
    "medium.com"
    "paypal.com"
    "ebay.com"
    "alibaba.com"
    "shopify.com"
    "spotify.com"
    "soundcloud.com"
    "vimeo.com"
    "dailymotion.com"
    "elastic.co"
    "docker.com"
    "kubernetes.io"
    "terraform.io"
    "ansible.com"
    "jenkins.io"
    "gitlab.com"
    "bitbucket.org"
    "atlassian.com"
    "jetbrains.com"
    "oracle.com"
    "ibm.com"
    "salesforce.com"
    "vmware.com"
    "citrix.com"
    "hp.com"
    "dell.com"
    "intel.com"
    "amd.com"
    "nvidia.com"
    "samsung.com"
    "lg.com"
    "sony.com"
    "nintendo.com"
    "playstation.com"
    "xbox.com"
    "steam.com"
    "epicgames.com"
    "ubisoft.com"
    "ea.com"
    "activision.com"
    "blizzard.com"
    "riot.games"
    "valve.com"
    "gog.com"
    "humble.com"
    "itch.io"
    "nasa.gov"
    "noaa.gov"
    "weather.com"
    "accuweather.com"
    "maps.google.com"
    "drive.google.com"
    "docs.google.com"
    "sheets.google.com"
    "slides.google.com"
    "calendar.google.com"
    "gmail.google.com"
    "photos.google.com"
    "translate.google.com"
    "news.google.com"
    "scholar.google.com"
    "books.google.com"
    "play.google.com"
    "store.google.com"
)

# Função para mostrar ajuda
show_help() {
    echo -e "${BLUE}DNS Stress Test - Teste de Estresse para Servidor DNS${NC}"
    echo ""
    echo "Uso: $0 [OPÇÕES]"
    echo ""
    echo "Opções:"
    echo "  -s, --server HOST      Servidor DNS a testar (padrão: 127.0.0.1)"
    echo "  -p, --port PORT        Porta do servidor DNS (padrão: 53)"
    echo "  -c, --concurrent NUM   Número de consultas simultâneas (padrão: 100)"
    echo "  -t, --total NUM        Total de consultas a realizar (padrão: 1000)"
    echo "  -T, --timeout SEC      Timeout por consulta em segundos (padrão: 5)"
    echo "  -q, --query-type TYPE  Tipo de consulta DNS (A, AAAA, MX, etc.) (padrão: A)"
    echo "  -o, --output FILE      Arquivo de saída para logs detalhados"
    echo "  -v, --verbose          Modo verboso"
    echo "  -h, --help             Mostra esta ajuda"
    echo ""
    echo "Exemplos:"
    echo "  $0                                    # Teste padrão"
    echo "  $0 -s 8.8.8.8 -c 50 -t 500          # Teste Google DNS"
    echo "  $0 -s 1.1.1.1 -c 200 -t 2000        # Teste Cloudflare DNS"
    echo "  $0 --server 192.168.1.1 --verbose   # Teste servidor local"
}

# Função para log
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$OUTPUT_FILE"
    if [ "$VERBOSE" = true ]; then
        echo -e "[$timestamp] [$level] $message"
    fi
}

# Função para realizar uma consulta DNS
perform_dns_query() {
    local domain=$1
    local query_id=$2
    local start_time=$(date +%s.%N)
    
    # Seleciona tipo de consulta aleatoriamente para mais realismo
    local query_types=("A" "AAAA" "MX" "NS" "TXT" "CNAME")
    local random_type=${query_types[$RANDOM % ${#query_types[@]}]}
    
    if [ "$QUERY_TYPE" != "A" ]; then
        random_type="$QUERY_TYPE"
    fi
    
    # Realiza a consulta usando dig
    local result=$(dig @"$DNS_SERVER" -p "$PORT" +time="$TIMEOUT" +tries=1 +short "$domain" "$random_type" 2>&1)
    local exit_code=$?
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l)
    
    # Log resultado
    if [ $exit_code -eq 0 ]; then
        log_message "INFO" "Query $query_id: $domain ($random_type) - SUCCESS - ${duration}s"
        echo "SUCCESS:$query_id:$domain:$random_type:$duration"
    else
        log_message "ERROR" "Query $query_id: $domain ($random_type) - FAILED - ${duration}s - $result"
        echo "FAILED:$query_id:$domain:$random_type:$duration:$result"
    fi
}

# Função para executar teste de estresse
run_stress_test() {
    echo -e "${BLUE}=== INICIANDO TESTE DE ESTRESSE DNS ===${NC}"
    echo -e "${YELLOW}Servidor DNS:${NC} $DNS_SERVER:$PORT"
    echo -e "${YELLOW}Consultas simultâneas:${NC} $CONCURRENT_QUERIES"
    echo -e "${YELLOW}Total de consultas:${NC} $TOTAL_QUERIES"
    echo -e "${YELLOW}Timeout:${NC} ${TIMEOUT}s"
    echo -e "${YELLOW}Tipo de consulta:${NC} $QUERY_TYPE"
    echo -e "${YELLOW}Log detalhado:${NC} $OUTPUT_FILE"
    echo ""
    
    # Testa conectividade básica
    echo -e "${BLUE}Testando conectividade básica...${NC}"
    if ! dig @"$DNS_SERVER" -p "$PORT" +time=5 google.com A > /dev/null 2>&1; then
        echo -e "${RED}ERRO: Não foi possível conectar ao servidor DNS $DNS_SERVER:$PORT${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Conectividade OK${NC}"
    echo ""
    
    # Inicializa contadores
    local queries_sent=0
    local successful_queries=0
    local failed_queries=0
    local total_time=0
    local min_time=999999
    local max_time=0
    
    # Cria arquivo temporário para resultados
    local temp_results="/tmp/dns_results_$$.tmp"
    
    echo -e "${BLUE}Iniciando teste de estresse...${NC}"
    local test_start_time=$(date +%s.%N)
    
    # Loop principal do teste
    while [ $queries_sent -lt $TOTAL_QUERIES ]; do
        local batch_size=$CONCURRENT_QUERIES
        if [ $((queries_sent + batch_size)) -gt $TOTAL_QUERIES ]; then
            batch_size=$((TOTAL_QUERIES - queries_sent))
        fi
        
        # Lança consultas em paralelo
        for ((i=0; i<batch_size; i++)); do
            local query_id=$((queries_sent + i + 1))
            local domain=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
            perform_dns_query "$domain" "$query_id" >> "$temp_results" &
        done
        
        # Aguarda conclusão do batch
        wait
        
        queries_sent=$((queries_sent + batch_size))
        
        # Mostra progresso
        local progress=$((queries_sent * 100 / TOTAL_QUERIES))
        echo -ne "\rProgresso: $queries_sent/$TOTAL_QUERIES consultas ($progress%) "
    done
    
    local test_end_time=$(date +%s.%N)
    local total_test_time=$(echo "$test_end_time - $test_start_time" | bc -l)
    
    echo ""
    echo -e "${BLUE}Processando resultados...${NC}"
    
    # Processa resultados
    while IFS=':' read -r status query_id domain query_type duration rest; do
        if [ "$status" = "SUCCESS" ]; then
            successful_queries=$((successful_queries + 1))
            total_time=$(echo "$total_time + $duration" | bc -l)
            if (( $(echo "$duration < $min_time" | bc -l) )); then
                min_time=$duration
            fi
            if (( $(echo "$duration > $max_time" | bc -l) )); then
                max_time=$duration
            fi
        else
            failed_queries=$((failed_queries + 1))
        fi
    done < "$temp_results"
    
    # Calcula estatísticas
    local avg_time=0
    if [ $successful_queries -gt 0 ]; then
        avg_time=$(echo "scale=3; $total_time / $successful_queries" | bc -l)
    fi
    
    local success_rate=$(echo "scale=2; $successful_queries * 100 / $TOTAL_QUERIES" | bc -l)
    local qps=$(echo "scale=2; $TOTAL_QUERIES / $total_test_time" | bc -l)
    
    # Remove arquivo temporário
    rm -f "$temp_results"
    
    # Exibe resultados
    echo ""
    echo -e "${GREEN}=== RESULTADOS DO TESTE ===${NC}"
    echo -e "${YELLOW}Total de consultas:${NC} $TOTAL_QUERIES"
    echo -e "${YELLOW}Consultas bem-sucedidas:${NC} $successful_queries"
    echo -e "${YELLOW}Consultas falharam:${NC} $failed_queries"
    echo -e "${YELLOW}Taxa de sucesso:${NC} ${success_rate}%"
    echo -e "${YELLOW}Tempo total do teste:${NC} ${total_test_time}s"
    echo -e "${YELLOW}Consultas por segundo:${NC} ${qps} QPS"
    
    if [ $successful_queries -gt 0 ]; then
        echo -e "${YELLOW}Tempo médio de resposta:${NC} ${avg_time}s"
        echo -e "${YELLOW}Tempo mínimo:${NC} ${min_time}s"
        echo -e "${YELLOW}Tempo máximo:${NC} ${max_time}s"
    fi
    
    echo -e "${YELLOW}Log detalhado salvo em:${NC} $OUTPUT_FILE"
    
    # Determina status do teste
    if (( $(echo "$success_rate >= 95" | bc -l) )); then
        echo -e "${GREEN}✓ TESTE PASSOU - Servidor DNS está respondendo adequadamente${NC}"
        return 0
    elif (( $(echo "$success_rate >= 80" | bc -l) )); then
        echo -e "${YELLOW}⚠ TESTE PARCIAL - Servidor DNS está com problemas leves${NC}"
        return 1
    else
        echo -e "${RED}✗ TESTE FALHOU - Servidor DNS está com problemas sérios${NC}"
        return 2
    fi
}

# Função para verificar dependências
check_dependencies() {
    local missing_deps=()
    
    if ! command -v dig &> /dev/null; then
        missing_deps+=("dnsutils")
    fi
    
    if ! command -v bc &> /dev/null; then
        missing_deps+=("bc")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${RED}ERRO: Dependências faltando: ${missing_deps[*]}${NC}"
        echo "Para instalar no Ubuntu/Debian:"
        echo "  sudo apt-get install dnsutils bc"
        echo "Para instalar no CentOS/RHEL:"
        echo "  sudo yum install bind-utils bc"
        exit 1
    fi
}

# Parse de argumentos da linha de comando
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--server)
            DNS_SERVER="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -c|--concurrent)
            CONCURRENT_QUERIES="$2"
            shift 2
            ;;
        -t|--total)
            TOTAL_QUERIES="$2"
            shift 2
            ;;
        -T|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -q|--query-type)
            QUERY_TYPE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Opção desconhecida: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Validações
if ! [[ "$CONCURRENT_QUERIES" =~ ^[0-9]+$ ]] || [ "$CONCURRENT_QUERIES" -lt 1 ] || [ "$CONCURRENT_QUERIES" -gt 1000 ]; then
    echo -e "${RED}ERRO: Número de consultas simultâneas deve ser entre 1 e 1000${NC}"
    exit 1
fi

if ! [[ "$TOTAL_QUERIES" =~ ^[0-9]+$ ]] || [ "$TOTAL_QUERIES" -lt 1 ]; then
    echo -e "${RED}ERRO: Total de consultas deve ser um número positivo${NC}"
    exit 1
fi

if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [ "$TIMEOUT" -lt 1 ] || [ "$TIMEOUT" -gt 60 ]; then
    echo -e "${RED}ERRO: Timeout deve ser entre 1 e 60 segundos${NC}"
    exit 1
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo -e "${RED}ERRO: Porta deve ser entre 1 e 65535${NC}"
    exit 1
fi

# Execução principal
main() {
    echo -e "${BLUE}DNS Stress Test v1.0${NC}"
    echo "Teste de estresse para servidores DNS"
    echo ""
    
    # Verifica dependências
    check_dependencies
    
    # Cria diretório para logs se necessário
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    
    # Inicia log
    log_message "INFO" "=== INICIANDO TESTE DE ESTRESSE DNS ==="
    log_message "INFO" "Servidor: $DNS_SERVER:$PORT"
    log_message "INFO" "Consultas simultâneas: $CONCURRENT_QUERIES"
    log_message "INFO" "Total de consultas: $TOTAL_QUERIES"
    log_message "INFO" "Timeout: ${TIMEOUT}s"
    log_message "INFO" "Tipo de consulta: $QUERY_TYPE"
    
    # Executa teste
    run_stress_test
    local exit_code=$?
    
    log_message "INFO" "=== TESTE DE ESTRESSE FINALIZADO ==="
    
    exit $exit_code
}

# Executa função principal se script foi chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi