# RESOLVIX - DNS Recursivo de Alta Performance

DNS Recursivo profissional baseado em Unbound com Prometheus para monitoramento.

**Autor:** Renylson Marques  
**Email:** renylsonm@gmail.com  
**Telefone:** (87) 98846-3681

## ✨ Características

- **Unbound v1.22.0**: DNS recursivo de alta performance
- **DNSSEC**: Validação segura de respostas DNS
- **IPv4 + IPv6**: Suporte completo
- **Prometheus**: Monitoramento e coleta de métricas
- **16 Threads**: Otimizado para milhões de requisições por segundo
- **512MB Cache**: Mensagens + RRSET

## 📋 Requisitos

- Debian 13+
- Root access
- Conexão com internet

## 🚀 Instalação

### Modo Interativo (com perguntas)

```bash
cd /root/resolvix
sudo bash install_dns.sh
```

### Modo Automático (sem perguntas)

```bash
cd /root/resolvix
echo -e "s\n2\n2\n\ns\ns" | sudo bash install_dns.sh
```

**Opções padrão automáticas:**
- Continuar: `s` (sim)
- Modo IP: `2` (Público)
- Versão IP: `2` (IPv4 + IPv6)
- Blocos IP: vazio (IPs privados padrão)
- Prometheus: `s` (sim)
- Confirmação final: `s` (sim)

## 🔧 Configuração Pós-Instalação

### Verificar Status

```bash
# Unbound
systemctl status unbound

# Exportador Prometheus
systemctl status unbound-exporter

# Prometheus
systemctl status prometheus
```

### Testar DNS

```bash
# Teste simples
dig @127.0.0.1 google.com

# Com nslookup
nslookup google.com 127.0.0.1

# Estatísticas
unbound-control stats
```

### Acessar Interfaces

- **Prometheus UI**: http://seu-ip:9090
- **Métricas Unbound**: http://seu-ip:9100/metrics

## 📚 Comandos Úteis

### Unbound

```bash
# Reiniciar
systemctl restart unbound

# Parar
systemctl stop unbound

# Logs em tempo real
journalctl -u unbound -f

# Verificar configuração
unbound-checkconf

# Recarregar sem reiniciar
unbound-control reload
```

### Prometheus

```bash
# Reiniciar
systemctl restart prometheus

# Parar
systemctl stop prometheus

# Logs
journalctl -u prometheus -f
```

### Exportador

```bash
# Reiniciar
systemctl restart unbound-exporter

# Logs
journalctl -u unbound-exporter -f

# Testar métricas
curl http://127.0.0.1:9100/metrics
```

## 🔐 Configurações de Segurança

### Modo de Operação

- **Local**: Aceita consultas de qualquer origem (desenvolvimento)
- **Público**: Restringe a IPs privados (produção)

### IPs Privados Permitidos

- `10.0.0.0/8` (IPv4)
- `172.16.0.0/12` (IPv4)
- `192.168.0.0/16` (IPv4)
- `100.64.0.0/10` (IPv4)
- `::1` (IPv6 loopback)
- `::ffff:0:0/96` (IPv6 mapped IPv4)

### Blocos Customizados (IPv4 e IPv6)

Durante a instalação, você pode adicionar blocos customizados:

**Exemplos:**
```
203.0.113.0/24 203.0.114.0/24 2001:db8::/32
```

Editar `/etc/unbound/unbound.conf` para adicionar/modificar:

```
# IPv4
access-control: 203.0.113.0/24 allow
access-control: 203.0.114.0/24 allow

# IPv6
access-control: 2001:db8::/32 allow
access-control: 2001:db9::/32 allow
```

Depois reiniciar:
```bash
systemctl restart unbound
```

## 📊 Monitoramento

### Métricas Disponíveis

- Queries totais
- Cache hits/misses
- DNSSEC queries e falhas
- Recursion queries
- Timeouts
- Respostas

### Prometheus Queries

```promql
# Queries por segundo
rate(unbound_thread0_num_queries[5m])

# Cache hit rate
rate(unbound_thread0_num_queries_cache_hit[5m])

# DNSSEC validations
rate(unbound_total_dnssec_queries[5m])
```

## 🛠️ Troubleshooting

### DNS não responde

```bash
# Verificar se Unbound está ativo
systemctl is-active unbound

# Ver logs
journalctl -u unbound --no-pager -n 20

# Testar localmente
dig @127.0.0.1 google.com
```

### Porta 53 já em uso

```bash
# Encontrar processo
sudo lsof -i :53

# Se systemd-resolved estiver usando:
sudo systemctl stop systemd-resolved
sudo systemctl mask systemd-resolved
```

### Prometheus não coleta métricas

```bash
# Verificar exportador
curl http://127.0.0.1:9100/health

# Ver métricas
curl http://127.0.0.1:9100/metrics

# Logs do Prometheus
journalctl -u prometheus -f
```

## 📁 Estrutura de Diretórios

```
/etc/unbound/                  # Configuração Unbound
/etc/prometheus/               # Configuração Prometheus
/opt/resolvix/                 # Scripts Resolvix
  ├── unbound_exporter.py      # Exportador Prometheus
  └── ...
/opt/prometheus/               # Binários Prometheus
/var/lib/prometheus/           # Dados Prometheus
/var/lib/unbound/              # Cache Unbound
```

## 🔄 Backup e Restore

### Backup

```bash
# Backup Unbound
cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup.$(date +%Y%m%d)

# Backup Prometheus
tar czf prometheus_backup.tar.gz /etc/prometheus /var/lib/prometheus
```

### Restore

```bash
# Restaurar Unbound
cp /etc/unbound/unbound.conf.backup.YYYYMMDD /etc/unbound/unbound.conf
systemctl restart unbound

# Restaurar Prometheus
tar xzf prometheus_backup.tar.gz -C /
systemctl restart prometheus
```

## 📝 Logs

- **Unbound**: `journalctl -u unbound`
- **Prometheus**: `journalctl -u prometheus`
- **Exportador**: `journalctl -u unbound-exporter`

## 🤝 Suporte

Para mais informações e documentação oficial:

- [Unbound Documentation](https://unbound.docs.nlnetlabs.nl/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Repositório RESOLVIX](https://github.com/renylson/resolvix)

## 📄 Licença

Este projeto é fornecido como está. Consulte o autor para mais informações.

---

**Última atualização:** 2025-10-29  
**Versão:** 2.1 (IPv4 + IPv6 em blocos customizados)
