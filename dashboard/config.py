import os
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'resolvix-dashboard-secret-key-2025'
    BIND_XML_URL = os.environ.get('BIND_XML_URL') or 'http://127.0.0.1:8053/'
    BIND_JSON_URL = os.environ.get('BIND_JSON_URL') or 'http://127.0.0.1:8053/json/v1/server'
    HOST = os.environ.get('DASHBOARD_HOST') or '0.0.0.0'
    PORT = int(os.environ.get('DASHBOARD_PORT') or 5000)
    DEBUG = os.environ.get('FLASK_DEBUG', '0').lower() in ['1', 'true', 'yes']
    UPDATE_INTERVAL = int(os.environ.get('UPDATE_INTERVAL') or 30)
    CACHE_TIMEOUT = int(os.environ.get('CACHE_TIMEOUT') or 60)
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.environ.get('LOG_FILE') or '/var/log/resolvix-dashboard.log'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT') or 3600)  # 1 hour
    LOGIN_DISABLED = False
    REMEMBER_COOKIE_DURATION = 86400  # 1 day
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    ACL_FILE = os.environ.get('ACL_FILE') or '/etc/bind/acl.conf'
    BACKUP_DIR = os.environ.get('BACKUP_DIR') or '/var/backups/resolvix'
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_LOGIN = "10 per minute"
class ProductionConfig(Config):
    DEBUG = False
    WTF_CSRF_ENABLED = True
class DevelopmentConfig(Config):
    DEBUG = True
    WTF_CSRF_ENABLED = False
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': ProductionConfig
}
