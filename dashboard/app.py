#!/usr/bin/env python3
"""
Resolvix Dashboard - Backend API
Autor: Renylson Marques <renylsonm@gmail.com>
Coleta e serve estatísticas do servidor DNS BIND9
"""

import json
import time
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template
from threading import Lock
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Cache para estatísticas com lock para thread safety
stats_cache = {}
cache_lock = Lock()
last_update = None

# URLs do BIND9
BIND_XML_URL = "http://127.0.0.1:8053/"
BIND_JSON_URL = "http://127.0.0.1:8053/json/v1/server"

def parse_xml_stats(xml_content):
    """Parseia estatísticas XML do BIND9"""
    try:
        root = ET.fromstring(xml_content)
        stats = {}
        
        # Server info
        server = root.find('.//server')
        if server is not None:
            stats['server'] = {
                'boot_time': server.find('boot-time').text if server.find('boot-time') is not None else None,
                'config_time': server.find('config-time').text if server.find('config-time') is not None else None,
                'current_time': server.find('current-time').text if server.find('current-time') is not None else None,
                'version': server.find('version').text if server.find('version') is not None else None
            }
        
        # Memory usage
        memory = root.find('.//memory')
        if memory is not None:
            total_malloc = 0
            total_inuse = 0
            
            for context in memory.findall('.//context'):
                malloced = context.find('malloced')
                inuse = context.find('inuse')
                
                if malloced is not None:
                    total_malloc += int(malloced.text)
                if inuse is not None:
                    total_inuse += int(inuse.text)
            
            stats['memory'] = {
                'total_malloc': total_malloc,
                'total_inuse': total_inuse,
                'malloc_mb': round(total_malloc / (1024 * 1024), 2),
                'inuse_mb': round(total_inuse / (1024 * 1024), 2)
            }
        
        # Socket statistics
        sockstat = root.find('.//counters[@type="sockstat"]')
        if sockstat is not None:
            stats['sockets'] = {}
            for counter in sockstat.findall('counter'):
                name = counter.get('name')
                value = int(counter.text)
                stats['sockets'][name] = value
        
        return stats
    except Exception as e:
        logging.error(f"Erro ao parsear XML: {e}")
        return {}

def fetch_json_stats():
    """Busca estatísticas JSON do BIND9"""
    try:
        response = requests.get(BIND_JSON_URL, timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"Erro ao buscar estatísticas JSON: {e}")
        return {}

def fetch_xml_stats():
    """Busca estatísticas XML do BIND9"""
    try:
        response = requests.get(BIND_XML_URL, timeout=5)
        response.raise_for_status()
        return parse_xml_stats(response.text)
    except Exception as e:
        logging.error(f"Erro ao buscar estatísticas XML: {e}")
        return {}

def calculate_metrics(json_data, xml_data):
    """Calcula métricas derivadas"""
    metrics = {}
    
    # Uptime calculation
    if 'boot-time' in json_data and 'current-time' in json_data:
        try:
            boot_time = datetime.fromisoformat(json_data['boot-time'].replace('Z', '+00:00'))
            current_time = datetime.fromisoformat(json_data['current-time'].replace('Z', '+00:00'))
            uptime_seconds = (current_time - boot_time).total_seconds()
            
            metrics['uptime'] = {
                'seconds': int(uptime_seconds),
                'formatted': format_uptime(uptime_seconds)
            }
        except:
            metrics['uptime'] = {'seconds': 0, 'formatted': 'Unknown'}
    
    # QPS calculation
    if 'opcodes' in json_data and 'QUERY' in json_data['opcodes']:
        total_queries = json_data['opcodes']['QUERY']
        if metrics.get('uptime', {}).get('seconds', 0) > 0:
            qps = total_queries / metrics['uptime']['seconds']
            metrics['qps'] = round(qps, 2)
        else:
            metrics['qps'] = 0
    
    # Success rate calculation
    if 'rcodes' in json_data:
        total_responses = sum(json_data['rcodes'].values())
        if total_responses > 0:
            success_responses = json_data['rcodes'].get('NOERROR', 0)
            success_rate = (success_responses / total_responses) * 100
            metrics['success_rate'] = round(success_rate, 2)
        else:
            metrics['success_rate'] = 0
    
    # Cache hit ratio
    if 'views' in json_data and '_default' in json_data['views']:
        cache_stats = json_data['views']['_default']['resolver']['cachestats']
        hits = cache_stats.get('CacheHits', 0)
        misses = cache_stats.get('CacheMisses', 0)
        total = hits + misses
        if total > 0:
            hit_ratio = (hits / total) * 100
            metrics['cache_hit_ratio'] = round(hit_ratio, 2)
        else:
            metrics['cache_hit_ratio'] = 0
    
    # Protocol distribution
    if 'nsstats' in json_data:
        udp_queries = json_data['nsstats'].get('QryUDP', 0)
        tcp_queries = json_data['nsstats'].get('QryTCP', 0)
        total = udp_queries + tcp_queries
        if total > 0:
            metrics['protocol_distribution'] = {
                'udp_percent': round((udp_queries / total) * 100, 1),
                'tcp_percent': round((tcp_queries / total) * 100, 1)
            }
        else:
            metrics['protocol_distribution'] = {'udp_percent': 0, 'tcp_percent': 0}
    
    return metrics

def format_uptime(seconds):
    """Formata uptime em formato legível"""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m {secs}s"
    elif hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"

def update_stats():
    """Atualiza cache de estatísticas"""
    global last_update
    
    with cache_lock:
        json_data = fetch_json_stats()
        xml_data = fetch_xml_stats()
        
        if json_data or xml_data:
            metrics = calculate_metrics(json_data, xml_data)
            
            stats_cache.update({
                'json': json_data,
                'xml': xml_data,
                'metrics': metrics,
                'last_updated': datetime.now().isoformat()
            })
            last_update = time.time()
            logging.info("Estatísticas atualizadas com sucesso")
        else:
            logging.warning("Falha ao obter estatísticas do BIND9")

@app.route('/')
def dashboard():
    """Página principal da dashboard"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    """API endpoint para todas as estatísticas"""
    # Atualiza se cache está vazio ou antigo (> 30 segundos)
    if not stats_cache or (last_update and time.time() - last_update > 30):
        update_stats()
    
    with cache_lock:
        return jsonify(stats_cache)

@app.route('/api/health')
def api_health():
    """Endpoint de health check"""
    try:
        # Testa conexão com BIND9
        response = requests.get(BIND_JSON_URL, timeout=2)
        bind_status = response.status_code == 200
    except:
        bind_status = False
    
    return jsonify({
        'status': 'healthy' if bind_status else 'unhealthy',
        'bind_accessible': bind_status,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/metrics')
def api_metrics():
    """Endpoint específico para métricas calculadas"""
    if not stats_cache or (last_update and time.time() - last_update > 30):
        update_stats()
    
    with cache_lock:
        return jsonify(stats_cache.get('metrics', {}))

if __name__ == '__main__':
    # Carrega estatísticas iniciais
    update_stats()
    
    # Inicia servidor Flask
    app.run(host='0.0.0.0', port=5000, debug=True)
# Configuração para produção
if __name__ == '__main__':
    import os
    import sys
    
    # Adiciona diretório atual ao path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        from config import config
        env = os.environ.get('FLASK_ENV', 'production')
        app_config = config.get(env, config['default'])
        
        app.config.from_object(app_config)
        
        # Configuração de logging para produção
        if not app.debug:
            import logging
            from logging.handlers import RotatingFileHandler
            
            if not os.path.exists('/var/log'):
                os.makedirs('/var/log', exist_ok=True)
            
            handler = RotatingFileHandler(
                '/var/log/resolvix-dashboard.log',
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5
            )
            handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s'
            ))
            handler.setLevel(logging.INFO)
            app.logger.addHandler(handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('Resolvix Dashboard startup')
        
        # Atualiza estatísticas iniciais
        update_stats()
        
        # Inicia servidor
        app.run(
            host=app_config.HOST,
            port=app_config.PORT,
            debug=app_config.DEBUG,
            threaded=True
        )
        
    except ImportError:
        # Fallback para configuração original
        update_stats()
        app.run(host='0.0.0.0', port=5000, debug=False)

# Configuração para produção
if __name__ == '__main__':
    import os
    import sys
    
    # Adiciona diretório atual ao path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        from config import config
        env = os.environ.get('FLASK_ENV', 'production')
        app_config = config.get(env, config['default'])
        
        app.config.from_object(app_config)
        
        # Configuração de logging para produção
        if not app.debug:
            import logging
            from logging.handlers import RotatingFileHandler
            
            if not os.path.exists('/var/log'):
                os.makedirs('/var/log', exist_ok=True)
            
            handler = RotatingFileHandler(
                '/var/log/resolvix-dashboard.log',
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5
            )
            handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s'
            ))
            handler.setLevel(logging.INFO)
            app.logger.addHandler(handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('Resolvix Dashboard startup')
        
        # Atualiza estatísticas iniciais
        update_stats()
        
        # Inicia servidor
        app.run(
            host=app_config.HOST,
            port=app_config.PORT,
            debug=app_config.DEBUG,
            threaded=True
        )
        
    except ImportError:
        # Fallback para configuração original
        update_stats()
        app.run(host='0.0.0.0', port=5000, debug=False)
