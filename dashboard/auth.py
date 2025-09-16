import json
import os
import bcrypt
import secrets
from datetime import datetime, timedelta
from flask import session, request, current_app
from flask_login import UserMixin, LoginManager
from functools import wraps
import logging
logger = logging.getLogger(__name__)
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username
    def get_id(self):
        return str(self.id)
class AuthManager:
    def __init__(self, data_dir="/opt/resolvix/dashboard/data"):
        self.data_dir = data_dir
        self.credentials_file = os.path.join(data_dir, "credentials.json")
        self.audit_log_file = os.path.join(data_dir, "audit.log")
        self._ensure_data_dir()
    def _ensure_data_dir(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir, mode=0o700)  # Somente owner pode acessar
    def _log_audit(self, action, username=None, ip=None, success=True):
        try:
            timestamp = datetime.now().isoformat()
            ip = ip or request.remote_addr if request else 'unknown'
            log_entry = {
                'timestamp': timestamp,
                'action': action,
                'username': username,
                'ip': ip,
                'success': success,
                'user_agent': request.headers.get('User-Agent', 'unknown') if request else 'unknown'
            }
            with open(self.audit_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Erro ao escrever log de auditoria: {e}")
    def hash_password(self, password):
        salt = bcrypt.gensalt(rounds=12)  # 12 rounds para boa segurança
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    def verify_password(self, password, hash_password):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hash_password.encode('utf-8'))
        except Exception as e:
            logger.error(f"Erro ao verificar senha: {e}")
            return False
    def create_admin_user(self, username, password):
        if self.user_exists():
            return False, "Usuário administrador já existe"
        if not self._validate_password_strength(password):
            return False, "Senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula, número e símbolo"
        hashed_password = self.hash_password(password)
        credentials = {
            'admin': {
                'username': username,
                'password_hash': hashed_password,
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'login_attempts': 0,
                'locked_until': None
            },
            'security': {
                'secret_key': secrets.token_hex(32),
                'csrf_token': secrets.token_hex(16),
                'created_at': datetime.now().isoformat()
            }
        }
        try:
            with open(self.credentials_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            os.chmod(self.credentials_file, 0o600)  # Somente owner pode ler/escrever
            self._log_audit('admin_user_created', username)
            return True, "Usuário administrador criado com sucesso"
        except Exception as e:
            logger.error(f"Erro ao criar usuário: {e}")
            return False, f"Erro ao salvar credenciais: {e}"
    def _validate_password_strength(self, password):
        if len(password) < 8:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        return has_upper and has_lower and has_digit and has_symbol
    def user_exists(self):
        return os.path.exists(self.credentials_file)
    def authenticate(self, username, password):
        if not self.user_exists():
            self._log_audit('login_attempt', username, success=False)
            return False, "Sistema não configurado"
        try:
            with open(self.credentials_file, 'r') as f:
                credentials = json.load(f)
            admin_data = credentials.get('admin', {})
            if admin_data.get('locked_until'):
                locked_until = datetime.fromisoformat(admin_data['locked_until'])
                if datetime.now() < locked_until:
                    self._log_audit('login_attempt_locked', username, success=False)
                    return False, "Conta temporariamente bloqueada"
                else:
                    admin_data['locked_until'] = None
                    admin_data['login_attempts'] = 0
            if (admin_data.get('username') == username and 
                self.verify_password(password, admin_data.get('password_hash', ''))):
                admin_data['login_attempts'] = 0
                admin_data['last_login'] = datetime.now().isoformat()
                admin_data['locked_until'] = None
                with open(self.credentials_file, 'w') as f:
                    json.dump(credentials, f, indent=2)
                self._log_audit('login_success', username, success=True)
                return True, "Login realizado com sucesso"
            else:
                attempts = admin_data.get('login_attempts', 0) + 1
                admin_data['login_attempts'] = attempts
                if attempts >= 5:
                    admin_data['locked_until'] = (datetime.now() + timedelta(minutes=15)).isoformat()
                    message = "Muitas tentativas. Conta bloqueada por 15 minutos"
                else:
                    message = f"Credenciais inválidas. Tentativas restantes: {5-attempts}"
                with open(self.credentials_file, 'w') as f:
                    json.dump(credentials, f, indent=2)
                self._log_audit('login_failed', username, success=False)
                return False, message
        except Exception as e:
            logger.error(f"Erro na autenticação: {e}")
            self._log_audit('login_error', username, success=False)
            return False, "Erro interno do sistema"
    def get_security_config(self):
        if not self.user_exists():
            return None
        try:
            with open(self.credentials_file, 'r') as f:
                credentials = json.load(f)
            return credentials.get('security', {})
        except Exception as e:
            logger.error(f"Erro ao ler configurações de segurança: {e}")
            return None
    def get_admin_info(self):
        if not self.user_exists():
            return None
        try:
            with open(self.credentials_file, 'r') as f:
                credentials = json.load(f)
            admin_data = credentials.get('admin', {}).copy()
            admin_data.pop('password_hash', None)  # Remove hash da senha
            return admin_data
        except Exception as e:
            logger.error(f"Erro ao ler informações do admin: {e}")
            return None
auth_manager = AuthManager()
login_manager = LoginManager()
@login_manager.user_loader
def load_user(user_id):
    admin_info = auth_manager.get_admin_info()
    if admin_info and str(user_id) == "admin":
        return User("admin", admin_info.get('username', 'admin'))
    return None
@login_manager.unauthorized_handler
def unauthorized():
    from flask import redirect, url_for, flash
    flash('Por favor, faça login para acessar esta página.', 'warning')
    return redirect(url_for('login'))
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_login import current_user
        if not current_user.is_authenticated:
            return unauthorized()
        return f(*args, **kwargs)
    return decorated_function
def setup_security_headers(app):
    @app.after_request
    def set_security_headers(response):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response
    return app