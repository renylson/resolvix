import json
import time
import requests
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, IPAddress
from threading import Lock
import logging
import ipaddress
import re
from auth import auth_manager, login_manager, require_auth, setup_security_headers, User
from acl_manager import acl_manager
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
csrf = CSRFProtect(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'info'
app = setup_security_headers(app)
stats_cache = {}
cache_lock = Lock()
last_update = None
BIND_JSON_URL = "http://127.0.0.1:8053/json/v1/server"
class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Entrar')
class ACLForm(FlaskForm):
    acl_name = SelectField('ACL', validators=[DataRequired()])
    ip_cidr = StringField('IP/CIDR', validators=[DataRequired(), Length(min=7, max=18)])
    action = SelectField('Ação', choices=[('add', 'Adicionar'), ('remove', 'Remover')], validators=[DataRequired()])
    submit = SubmitField('Executar')
class NewACLForm(FlaskForm):
    name = StringField('Nome da ACL', validators=[DataRequired(), Length(min=3, max=30)])
    description = TextAreaField('Descrição (opcional)')
    submit = SubmitField('Criar ACL')
def fetch_json_stats():
    try:
        response = requests.get(BIND_JSON_URL, timeout=5)
        response.raise_for_status()
        data = response.json()
        stats = {
            'server_info': {},
            'memory': {},
            'queries': {},
            'cache': {},
            'resolver': {},
            'dnssec': {},
            'network': {},
            'raw': data
        }
        if 'version' in data:
            stats['server_info']['version'] = data['version']
        if 'boot-time' in data:
            stats['server_info']['boot_time'] = data['boot-time']
        if 'config-time' in data:
            stats['server_info']['config_time'] = data['config-time']
        if 'current-time' in data:
            stats['server_info']['current_time'] = data['current-time']
        if 'opcodes' in data:
            stats['queries']['opcodes'] = data['opcodes']
            stats['queries']['total_queries'] = data['opcodes'].get('QUERY', 0)
        if 'rcodes' in data:
            stats['queries']['rcodes'] = data['rcodes']
            stats['queries']['noerror'] = data['rcodes'].get('NOERROR', 0)
            stats['queries']['nxdomain'] = data['rcodes'].get('NXDOMAIN', 0)
            stats['queries']['servfail'] = data['rcodes'].get('SERVFAIL', 0)
        if 'qtypes' in data:
            stats['queries']['qtypes'] = data['qtypes']
        if 'nsstats' in data:
            stats['network'] = data['nsstats']
            stats['network']['tcp_requests'] = data['nsstats'].get('ReqTCP', 0)
            stats['network']['udp_requests'] = data['nsstats'].get('Requestv4', 0) - data['nsstats'].get('ReqTCP', 0)
            stats['network']['truncated_responses'] = data['nsstats'].get('TruncatedResp', 0)
            stats['network']['successful_queries'] = data['nsstats'].get('QrySuccess', 0)
            stats['network']['recursive_queries'] = data['nsstats'].get('QryRecursion', 0)
        if 'views' in data:
            for view_name, view_data in data['views'].items():
                if 'resolver' in view_data and 'stats' in view_data['resolver']:
                    resolver_stats = view_data['resolver']['stats']
                    stats['resolver'][view_name] = resolver_stats
                    if view_name == '_default':  # View principal
                        stats['resolver']['queries_v4'] = resolver_stats.get('Queryv4', 0)
                        stats['resolver']['queries_v6'] = resolver_stats.get('Queryv6', 0)
                        stats['resolver']['validation_attempts'] = resolver_stats.get('ValAttempt', 0)
                        stats['resolver']['validation_ok'] = resolver_stats.get('ValOk', 0)
                        stats['resolver']['validation_neg_ok'] = resolver_stats.get('ValNegOk', 0)
                        stats['resolver']['retries'] = resolver_stats.get('Retry', 0)
                if 'resolver' in view_data:
                    resolver_data = view_data['resolver']
                    if 'cache' in resolver_data:
                        cache_data = resolver_data['cache']
                        stats['cache'][view_name] = cache_data
                        if view_name == '_default':  # Cache principal
                            total_cache = sum(cache_data.values()) if cache_data else 0
                            stats['cache']['total_rrsets'] = total_cache
                    if 'cachestats' in resolver_data and view_name == '_default':
                        cache_stats = resolver_data['cachestats']
                        stats['cache']['hits'] = cache_stats.get('CacheHits', 0)
                        stats['cache']['misses'] = cache_stats.get('CacheMisses', 0)
                        stats['cache']['query_hits'] = cache_stats.get('QueryHits', 0)
                        stats['cache']['query_misses'] = cache_stats.get('QueryMisses', 0)
                        stats['cache']['nodes'] = cache_stats.get('CacheNodes', 0)
                        stats['cache']['tree_mem'] = cache_stats.get('TreeMemInUse', 0)
                        stats['cache']['heap_mem'] = cache_stats.get('HeapMemInUse', 0)
        if stats['cache'].get('hits') and stats['cache'].get('misses'):
            total_cache_ops = stats['cache']['hits'] + stats['cache']['misses']
            stats['cache']['hit_rate'] = round((stats['cache']['hits'] / total_cache_ops) * 100, 2)
        if stats['resolver'].get('validation_attempts'):
            val_total = stats['resolver']['validation_attempts']
            val_ok = stats['resolver'].get('validation_ok', 0)
            val_neg_ok = stats['resolver'].get('validation_neg_ok', 0)
            stats['dnssec']['validation_success_rate'] = round(((val_ok + val_neg_ok) / val_total) * 100, 2)
        total_memory = 0
        if stats['cache'].get('tree_mem'):
            total_memory += stats['cache']['tree_mem']
        if stats['cache'].get('heap_mem'):
            total_memory += stats['cache']['heap_mem']
        stats['memory']['cache_memory_bytes'] = total_memory
        stats['memory']['cache_memory_mb'] = round(total_memory / (1024 * 1024), 2)
        return stats
    except Exception as e:
        logging.error(f"Erro ao buscar estatísticas JSON: {e}")
        return {}
def fetch_xml_stats():
    """Busca estatísticas XML do BIND9"""
    try:
        response = requests.get(BIND_XML_URL, timeout=5)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logging.error(f"Erro ao buscar estatísticas XML: {e}")
        return ""
def calculate_metrics(stats):
    """Calcula métricas derivadas das estatísticas JSON"""
    metrics = {}
    try:
        if stats.get('server_info', {}).get('boot_time'):
            boot_time_str = stats['server_info']['boot_time']
            current_time_str = stats['server_info'].get('current_time', datetime.now(timezone.utc).isoformat())
            try:
                boot_time = datetime.fromisoformat(boot_time_str.replace('Z', '+00:00'))
                current_time = datetime.fromisoformat(current_time_str.replace('Z', '+00:00'))
                uptime_seconds = (current_time - boot_time).total_seconds()
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                metrics['uptime_seconds'] = int(uptime_seconds)
                metrics['uptime_formatted'] = f"{days}d {hours}h {minutes}m"
                total_queries = stats.get('queries', {}).get('total_queries', 0)
                if uptime_seconds > 0:
                    metrics['queries_per_second'] = round(total_queries / uptime_seconds, 2)
                else:
                    metrics['queries_per_second'] = 0
            except Exception as e:
                logging.error(f"Erro ao calcular uptime: {e}")
                metrics['uptime_formatted'] = "N/A"
                metrics['uptime_seconds'] = 0
        noerror = stats.get('queries', {}).get('noerror', 0)
        total_responses = sum(stats.get('queries', {}).get('rcodes', {}).values())
        if total_responses > 0:
            metrics['success_rate'] = round((noerror / total_responses) * 100, 2)
        else:
            metrics['success_rate'] = 0
        metrics['cache_hit_rate'] = stats.get('cache', {}).get('hit_rate', 0)
        tcp_requests = stats.get('network', {}).get('tcp_requests', 0)
        udp_requests = stats.get('network', {}).get('udp_requests', 0)
        total_network_requests = tcp_requests + udp_requests
        if total_network_requests > 0:
            metrics['tcp_percentage'] = round((tcp_requests / total_network_requests) * 100, 2)
            metrics['udp_percentage'] = round((udp_requests / total_network_requests) * 100, 2)
        else:
            metrics['tcp_percentage'] = 0
            metrics['udp_percentage'] = 0
        recursive = stats.get('network', {}).get('recursive_queries', 0)
        successful = stats.get('network', {}).get('successful_queries', 0)
        if successful > 0:
            metrics['recursion_rate'] = round((recursive / successful) * 100, 2)
        else:
            metrics['recursion_rate'] = 0
        metrics['dnssec_validation_rate'] = stats.get('dnssec', {}).get('validation_success_rate', 0)
        cache_memory_mb = stats.get('memory', {}).get('cache_memory_mb', 0)
        total_queries = stats.get('queries', {}).get('total_queries', 1)  # Evitar divisão por zero
        metrics['memory_per_1k_queries'] = round((cache_memory_mb / total_queries) * 1000, 3)
        qtypes = stats.get('queries', {}).get('qtypes', {})
        if qtypes:
            sorted_qtypes = sorted(qtypes.items(), key=lambda x: x[1], reverse=True)
            metrics['top_query_types'] = sorted_qtypes[:5]  # Top 5
        servfail_rate = 0
        if total_responses > 0:
            servfail = stats.get('queries', {}).get('servfail', 0)
            servfail_rate = (servfail / total_responses) * 100
        if servfail_rate > 5:
            metrics['server_status'] = 'warning'
        elif servfail_rate > 10:
            metrics['server_status'] = 'critical'
        else:
            metrics['server_status'] = 'healthy'
    except Exception as e:
        logging.error(f"Erro ao calcular métricas: {e}")
    return metrics
def update_stats():
    """Atualiza cache de estatísticas usando apenas endpoint JSON"""
    global last_update
    with cache_lock:
        try:
            stats = fetch_json_stats()
            if stats:
                metrics = calculate_metrics(stats)
                stats_cache.clear()
                stats_cache.update({
                    'stats': stats,
                    'metrics': metrics,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'ok'
                })
                last_update = time.time()
                logging.info("Estatísticas atualizadas com sucesso (JSON-only)")
            else:
                stats_cache.update({
                    'status': 'error',
                    'message': 'Falha ao obter dados do BIND9',
                    'timestamp': datetime.now().isoformat()
                })
        except Exception as e:
            logging.error(f"Erro ao atualizar estatísticas: {e}")
            stats_cache.update({
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
def api_login_required(f):
    """Decorador que retorna JSON em caso de não autenticação"""
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'error': 'Não autenticado', 'redirect': '/login'}), 401
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        success, message = auth_manager.authenticate(username, password)
        if success:
            user = User("admin", username)
            login_user(user, remember=True)
            flash('Login realizado com sucesso!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash(message, 'error')
    return render_template('login.html', form=form)
@app.route('/logout')
@login_required
def logout():
    """Logout do usuário"""
    logout_user()
    flash('Logout realizado com sucesso!', 'info')
    return redirect(url_for('login'))
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Página principal da dashboard"""
    if not stats_cache or (last_update and time.time() - last_update > 30):
        update_stats()
    return render_template('dashboard.html', user=current_user)
@app.route('/acl-management')
@login_required
def acl_management():
    """Página de gerenciamento de ACLs"""
    try:
        acls = acl_manager.get_all_acls()
        acl_stats = acl_manager.get_statistics()
        acl_form = ACLForm()
        acl_form.acl_name.choices = [(name, name) for name in acls.keys()]
        new_acl_form = NewACLForm()
        return render_template('acl_management.html', 
                             acls=acls, 
                             acl_stats=acl_stats,
                             acl_form=acl_form,
                             new_acl_form=new_acl_form,
                             user=current_user)
    except Exception as e:
        flash(f'Erro ao carregar ACLs: {e}', 'error')
        return redirect(url_for('dashboard'))
@app.route('/api/test', methods=['GET'])
def api_test():
    """Endpoint de teste sem autenticação para verificar estatísticas"""
    try:
        stats = fetch_json_stats()
        if stats:
            metrics = calculate_metrics(stats)
            return jsonify({
                'status': 'ok',
                'uptime': metrics.get('uptime_formatted', 'N/A'),
                'uptime_seconds': metrics.get('uptime_seconds', 0),
                'queries_per_second': metrics.get('queries_per_second', 0),
                'total_queries': stats.get('queries', {}).get('total_queries', 0),
                'cache_hit_rate': metrics.get('cache_hit_rate', 0),
                'success_rate': metrics.get('success_rate', 0),
                'boot_time': stats.get('server_info', {}).get('boot_time', 'N/A'),
                'current_time': stats.get('server_info', {}).get('current_time', 'N/A'),
                'version': stats.get('server_info', {}).get('version', 'N/A'),
                'memory_mb': stats.get('memory', {}).get('cache_memory_mb', 0)
            })
        else:
            return jsonify({'status': 'error', 'message': 'Falha ao obter dados do BIND9'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint para todas as estatísticas"""
    if not stats_cache or (last_update and time.time() - last_update > 30):
        update_stats()
    with cache_lock:
        return jsonify(stats_cache)
@app.route('/api/acl', methods=['GET'])
@app.route('/api/acl/list', methods=['GET'])
@login_required
def api_get_acls():
    """API para obter todas as ACLs"""
    try:
        acls = acl_manager.get_all_acls()
        return jsonify({'success': True, 'acls': acls})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/acl/add', methods=['POST'])
@csrf.exempt
@api_login_required
def api_acl_add():
    """API para adicionar IP a uma ACL"""
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type deve ser application/json'}), 400
        data = request.get_json()
        acl_name = data.get('acl_name')
        ip_cidr = data.get('ip')
        if not all([acl_name, ip_cidr]):
            return jsonify({'success': False, 'error': 'Parâmetros acl_name e ip são obrigatórios'}), 400
        try:
            ipaddress.ip_network(ip_cidr, strict=False)
        except ValueError:
            try:
                ipaddress.ip_address(ip_cidr)
            except ValueError:
                return jsonify({'success': False, 'error': 'Formato de IP/CIDR inválido'}), 400
        success, message = acl_manager.add_ip_to_acl(acl_name, ip_cidr)
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/acl/remove', methods=['POST'])
@csrf.exempt
@api_login_required
def api_acl_remove():
    """API para remover IP de uma ACL"""
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type deve ser application/json'}), 400
        data = request.get_json()
        acl_name = data.get('acl_name')
        ip_cidr = data.get('ip')
        if not all([acl_name, ip_cidr]):
            return jsonify({'success': False, 'error': 'Parâmetros acl_name e ip são obrigatórios'}), 400
        try:
            ipaddress.ip_network(ip_cidr, strict=False)
        except ValueError:
            try:
                ipaddress.ip_address(ip_cidr)
            except ValueError:
                return jsonify({'success': False, 'error': 'Formato de IP/CIDR inválido'}), 400
        success, message = acl_manager.remove_ip_from_acl(acl_name, ip_cidr)
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/acl/<acl_name>', methods=['GET'])
@login_required
def api_get_acl(acl_name):
    """API para obter uma ACL específica"""
    try:
        acl = acl_manager.get_acl(acl_name)
        if acl is not None:
            return jsonify({'success': True, 'acl': {acl_name: acl}})
        else:
            return jsonify({'success': False, 'error': 'ACL não encontrada'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/acl/manage', methods=['POST'])
@login_required
def api_manage_acl():
    """API para gerenciar ACLs (adicionar/remover IPs)"""
    try:
        validate_csrf(request.form.get('csrf_token'))
        acl_name = request.form.get('acl_name')
        ip_cidr = request.form.get('ip_cidr')
        action = request.form.get('action')
        if not all([acl_name, ip_cidr, action]):
            return jsonify({'success': False, 'error': 'Parâmetros obrigatórios faltando'}), 400
        try:
            ipaddress.ip_network(ip_cidr, strict=False)
        except ValueError:
            try:
                ipaddress.ip_address(ip_cidr)
            except ValueError:
                return jsonify({'success': False, 'error': 'Formato de IP/CIDR inválido'}), 400
        if action == 'add':
            success, message = acl_manager.add_ip_to_acl(acl_name, ip_cidr)
        elif action == 'remove':
            success, message = acl_manager.remove_ip_from_acl(acl_name, ip_cidr)
        else:
            return jsonify({'success': False, 'error': 'Ação inválida'}), 400
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/acl/create', methods=['POST'])
@login_required
def api_create_acl():
    """API para criar nova ACL"""
    try:
        validate_csrf(request.form.get('csrf_token'))
        acl_name = request.form.get('name')
        if not acl_name:
            return jsonify({'success': False, 'error': 'Nome da ACL é obrigatório'}), 400
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', acl_name):
            return jsonify({'success': False, 'error': 'Nome inválido para ACL'}), 400
        success, message = acl_manager.create_acl(acl_name)
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/acl/<acl_name>/delete', methods=['POST'])
@login_required
def api_delete_acl(acl_name):
    """API para deletar ACL"""
    try:
        validate_csrf(request.form.get('csrf_token'))
        success, message = acl_manager.delete_acl(acl_name)
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/health')
def api_health():
    """Endpoint de health check"""
    try:
        response = requests.get(BIND_JSON_URL, timeout=2)
        bind_status = response.status_code == 200
    except:
        bind_status = False
    return jsonify({
        'status': 'healthy' if bind_status else 'unhealthy',
        'bind_accessible': bind_status,
        'authenticated': current_user.is_authenticated if hasattr(current_user, 'is_authenticated') else False,
        'timestamp': datetime.now().isoformat()
    })
@app.route('/api')
def api_info():
    """Endpoint principal da API - lista endpoints disponíveis"""
    return jsonify({
        'name': 'Resolvix Dashboard API',
        'version': '2.0.0',
        'description': 'API para monitoramento do servidor DNS BIND9 com autenticação',
        'endpoints': {
            '/api': 'Informações da API',
            '/api/health': 'Status de saúde do serviço',
            '/api/stats': 'Estatísticas completas do DNS (auth required)',
            '/api/acl': 'Gerenciamento de ACLs (auth required)'
        },
        'timestamp': datetime.now().isoformat()
    })
@app.route('/api/metrics')
@login_required
def api_metrics():
    """Endpoint específico para métricas calculadas"""
    if not stats_cache or (last_update and time.time() - last_update > 30):
        update_stats()
    with cache_lock:
        return jsonify(stats_cache.get('metrics', {}))
if __name__ == '__main__':
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from config import config
        env = os.environ.get('FLASK_ENV', 'production')
        app_config = config.get(env, config['default'])
        app.config.from_object(app_config)
        security_config = auth_manager.get_security_config()
        if security_config and 'secret_key' in security_config:
            app.config['SECRET_KEY'] = security_config['secret_key']
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
        if not auth_manager.user_exists():
            app.logger.warning('Sistema não configurado - executar instalação primeiro')
        update_stats()
        app.run(
            host=app_config.HOST,
            port=app_config.PORT,
            debug=app_config.DEBUG,
            threaded=True
        )
    except ImportError:
        app.config['SECRET_KEY'] = 'resolvix-dashboard-fallback-key'
        security_config = auth_manager.get_security_config()
        if security_config and 'secret_key' in security_config:
            app.config['SECRET_KEY'] = security_config['secret_key']
        if not auth_manager.user_exists():
            print("AVISO: Sistema não configurado - execute './resolvix.sh install' primeiro")
        update_stats()
        app.run(host='0.0.0.0', port=5000, debug=False)
