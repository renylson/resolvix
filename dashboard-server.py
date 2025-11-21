#!/usr/bin/env python3
"""
RESOLVIX - Web Dashboard Server
Servidor web profissional para exibir dashboard de métricas DNS
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import subprocess

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DashboardHandler(BaseHTTPRequestHandler):
    """Handler HTTP para servir dashboard e métricas"""

    DASHBOARD_FILE = '/root/resolvix/web-dashboard.html'

    def do_GET(self):
        """Lidar com requisições GET"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/' or path == '/dashboard':
            self.serve_dashboard()

        elif path == '/api/unbound-stats':
            self.serve_unbound_stats_json()

        elif path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = json.dumps({
                'status': 'healthy',
                'service': 'resolvix-dashboard',
                'version': '1.0'
            })
            self.wfile.write(response.encode('utf-8'))

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'404 Not Found\n')

    def serve_dashboard(self):
        try:
            if not os.path.exists(self.DASHBOARD_FILE):
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Dashboard file not found\n')
                return

            with open(self.DASHBOARD_FILE, 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(content))
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            self.wfile.write(content)

        except Exception as e:
            logger.error(f"Erro ao servir dashboard: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f'Error: {str(e)}\n'.encode('utf-8'))

    def serve_unbound_stats_json(self):
        """Servir métricas do Unbound em JSON, agregando por thread para o frontend"""
        try:
            result = subprocess.run(
                ['unbound-control', 'stats'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                self.send_response(503)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unbound not available'}).encode('utf-8'))
                return
            metrics = self.parse_unbound_stats(result.stdout)

            aggregations = {
                'unbound_total_queries': 'num.queries',
                'unbound_total_cached_queries': 'num.cachehits',
                'unbound_total_recursion_queries': 'num.recursivereplies',
                'unbound_total_dnssec_queries': 'num.query_dnssec',
                'unbound_total_dnssec_bogus': 'num.answer_bogus',
                'unbound_total_responses_servfail': 'num.answer_servfail',
                'unbound_total_requestlist_current_all': 'requestlist.current.all',
                'unbound_total_recursion_time_timeouts': 'recursion.time.timeouts',
                'unbound_total_prefetch': 'num.prefetch',
            }
            for key, suffix in aggregations.items():
                total = 0
                for mkey, value in metrics.items():
                    if mkey.startswith('thread') and mkey.endswith(suffix):
                        if isinstance(value, (int, float)):
                            total += value
                metrics[key] = total

            self.send_response(200)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(metrics).encode('utf-8'))
        except Exception as e:
            logger.error(f"Erro ao servir métricas: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))

    @staticmethod
    def parse_unbound_stats(stats_output):
        """Parse das estatísticas do Unbound"""
        metrics = {}

        for line in stats_output.split('\n'):
            if not line.strip():
                continue

            parts = line.split('=')
            if len(parts) != 2:
                continue

            key, value = parts[0].strip(), parts[1].strip()

            try:
                if '.' in value:
                    metrics[key] = float(value)
                else:
                    metrics[key] = int(value)
            except ValueError:
                metrics[key] = value

        return metrics

    @staticmethod
    def format_prometheus(metrics):
        """Formatar métricas em formato Prometheus, agregando por thread e expondo totais"""
        output = []

        output.append("# HELP unbound_info Informações do servidor Unbound")
        output.append("# TYPE unbound_info gauge")
        output.append('unbound_info{version="1.22.0"} 1')
        output.append("")

        aggregations = {
            'unbound_total_queries': 'num_queries',
            'unbound_total_cached_queries': 'num_cachehits',
            'unbound_total_recursion_queries': 'num_recursivereplies',
            'unbound_total_dnssec_queries': 'num_query_dnssec',
            'unbound_total_dnssec_bogus': 'num_answer_bogus',
            'unbound_total_responses_servfail': 'num_answer_servfail',
            'unbound_total_requestlist_current_all': 'requestlist_current_all',
            'unbound_total_recursion_time_timeouts': 'recursion_time_timeouts',
            'unbound_total_prefetch': 'num_prefetch',
        }

        totals = {k: 0 for k in aggregations}

        for key, value in metrics.items():
            parts = key.split('.')
            if len(parts) < 3:
                continue
            thread_prefix, metric_type, metric_name = parts[0], parts[1], '.'.join(parts[2:])
            if not thread_prefix.startswith('thread'):
                continue
            for total_name, suffix in aggregations.items():
                if metric_type == 'num' and metric_name == suffix.replace('num_', ''):
                    if isinstance(value, (int, float)):
                        totals[total_name] += value
                elif metric_type + '.' + metric_name == suffix:
                    if isinstance(value, (int, float)):
                        totals[total_name] += value

        for total_name, total_value in totals.items():
            output.append(f'{total_name} {total_value}')

        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                metric_name = 'unbound_' + key.replace('.', '_')
                output.append(f'{metric_name} {value}')

        return '\n'.join(output) + '\n'

    def log_message(self, format, *args):
        """Log de requisições HTTP"""
        logger.info(f"{self.client_address[0]} - {format % args}")


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description='RESOLVIX - Web Dashboard Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemplos de uso:
  %(prog)s                    # Iniciar em 0.0.0.0:8080
  %(prog)s --port 9000        # Iniciar em porta customizada
  %(prog)s --host localhost   # Iniciar apenas em localhost
        '''
    )

    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host para bind (padrão: 0.0.0.0)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Porta para bind (padrão: 8080)'
    )

    parser.add_argument(
        '--dashboard',
        default='/root/resolvix/web-dashboard.html',
        help='Caminho para arquivo dashboard'
    )

    args = parser.parse_args()

    if not os.path.exists(args.dashboard):
        logger.error(f"Dashboard file not found: {args.dashboard}")
        sys.exit(1)

    DashboardHandler.DASHBOARD_FILE = args.dashboard

    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, DashboardHandler)

    logger.info(f"RESOLVIX Dashboard Server iniciado")
    logger.info(f"Listening on {args.host}:{args.port}")
    logger.info(f"Acessível em: http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}")
    logger.info(f"Dashboard: http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}/dashboard")
    logger.info(f"Métricas: http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}/metrics")
    logger.info(f"Health: http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}/health")
    logger.info("Pressione Ctrl+C para parar o servidor")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Encerrando servidor...")
        httpd.shutdown()


if __name__ == '__main__':
    main()
