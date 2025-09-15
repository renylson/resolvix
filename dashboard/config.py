#!/usr/bin/env python3
"""
Resolvix Dashboard - Configuração de Produção
"""

import os

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'resolvix-dashboard-secret-key-2025'
    
    # BIND9 settings
    BIND_XML_URL = os.environ.get('BIND_XML_URL') or 'http://127.0.0.1:8053/'
    BIND_JSON_URL = os.environ.get('BIND_JSON_URL') or 'http://127.0.0.1:8053/json/v1/server'
    
    # Dashboard settings
    HOST = os.environ.get('DASHBOARD_HOST') or '0.0.0.0'
    PORT = int(os.environ.get('DASHBOARD_PORT') or 8080)
    DEBUG = os.environ.get('FLASK_DEBUG', '0').lower() in ['1', 'true', 'yes']
    
    # Update interval (seconds)
    UPDATE_INTERVAL = int(os.environ.get('UPDATE_INTERVAL') or 30)
    
    # Cache settings
    CACHE_TIMEOUT = int(os.environ.get('CACHE_TIMEOUT') or 60)
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.environ.get('LOG_FILE') or '/var/log/resolvix-dashboard.log'

class ProductionConfig(Config):
    DEBUG = False
    
class DevelopmentConfig(Config):
    DEBUG = True

# Default configuration
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': ProductionConfig
}
