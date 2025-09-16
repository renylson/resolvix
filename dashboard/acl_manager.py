import os
import re
import json
import shutil
import subprocess
import ipaddress
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import logging
logger = logging.getLogger(__name__)
class ACLManager:
    def __init__(self, acl_file="/etc/bind/acl.conf"):
        self.acl_file = acl_file
        self.backup_dir = "/var/backups/resolvix"
        self.audit_log = "/var/log/resolvix/acl.log"
        self._ensure_backup_dir()
    def _ensure_backup_dir(self):
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir, mode=0o755)
    def _log_action(self, action: str, details: Dict, success: bool = True):
        try:
            timestamp = datetime.now().isoformat()
            log_entry = {
                'timestamp': timestamp,
                'action': action,
                'details': details,
                'success': success
            }
            with open(self.audit_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Erro ao escrever log de ACL: {e}")
    def _backup_config(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(self.backup_dir, f"acl.conf.backup.{timestamp}")
        try:
            if os.path.exists(self.acl_file):
                shutil.copy2(self.acl_file, backup_file)
                logger.info(f"Backup criado: {backup_file}")
                return backup_file
        except Exception as e:
            logger.error(f"Erro ao criar backup: {e}")
            raise Exception(f"Falha ao criar backup: {e}")
        return backup_file
    def _validate_cidr(self, cidr: str) -> bool:
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    def _validate_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    def _parse_acl_file(self) -> Dict[str, List[str]]:
        acls = {}
        if not os.path.exists(self.acl_file):
            logger.warning(f"Arquivo ACL não encontrado: {self.acl_file}")
            return acls
        try:
            with open(self.acl_file, 'r') as f:
                content = f.read()
            acl_pattern = r'acl\s+"([^"]+)"\s*\{([^}]+)\};'
            matches = re.findall(acl_pattern, content, re.MULTILINE | re.DOTALL)
            for acl_name, acl_content in matches:
                ips = []
                lines = acl_content.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('//') and not line.startswith('#'):
                        ip = re.sub(r'[;\s]*(//.*|#.*)?$', '', line).strip()
                        if ip and ip != 'none':
                            ips.append(ip)
                acls[acl_name] = ips
            return acls
        except Exception as e:
            logger.error(f"Erro ao parsear arquivo ACL: {e}")
            raise Exception(f"Erro ao ler configuração ACL: {e}")
    def _write_acl_file(self, acls: Dict[str, List[str]]):
        try:
            self._backup_config()
            content = "// Resolvix - Access Control Lists\n"
            content += f"// Atualizado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            for acl_name, ips in acls.items():
                content += f'acl "{acl_name}" {{\n'
                if not ips or (len(ips) == 1 and ips[0] == 'none'):
                    content += "    none;\n"
                else:
                    for ip in ips:
                        content += f"    {ip};\n"
                content += "};\n\n"
            with open(self.acl_file, 'w') as f:
                f.write(content)
            logger.info("Arquivo ACL atualizado com sucesso")
        except Exception as e:
            logger.error(f"Erro ao escrever arquivo ACL: {e}")
            raise Exception(f"Falha ao atualizar configuração: {e}")
    def _test_bind_config(self) -> bool:
        try:
            result = subprocess.run(
                ['/usr/bin/named-checkconf'], 
                capture_output=True, 
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Erro ao testar configuração BIND: {e}")
            return False
    def _reload_bind(self) -> bool:
        try:
            test_result = subprocess.run(
                ['/usr/bin/named-checkconf'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if test_result.returncode != 0:
                logger.error(f"Configuração BIND inválida: {test_result.stderr}")
                return False
            result = subprocess.run(
                ['/usr/sbin/rndc', 'reload'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info("BIND9 recarregado com sucesso via rndc")
                return True
            else:
                logger.warning(f"rndc reload falhou: {result.stderr}")
                logger.info("Tentando fallback com systemctl reload...")
                result = subprocess.run(
                    ['systemctl', 'reload', 'bind9'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result.returncode == 0:
                    logger.info("BIND9 recarregado com sucesso via systemctl")
                    return True
                else:
                    logger.error(f"Erro ao recarregar BIND9: {result.stderr}")
                    return False
        except Exception as e:
            logger.error(f"Erro ao recarregar BIND9: {e}")
            return False
    def get_all_acls(self) -> Dict[str, List[str]]:
        try:
            acls = self._parse_acl_file()
            self._log_action('get_acls', {'count': len(acls)})
            return acls
        except Exception as e:
            self._log_action('get_acls', {'error': str(e)}, success=False)
            raise
    def get_acl(self, acl_name: str) -> Optional[List[str]]:
        try:
            acls = self._parse_acl_file()
            acl = acls.get(acl_name)
            self._log_action('get_acl', {'name': acl_name, 'found': acl is not None})
            return acl
        except Exception as e:
            self._log_action('get_acl', {'name': acl_name, 'error': str(e)}, success=False)
            raise
    def add_ip_to_acl(self, acl_name: str, ip_cidr: str) -> Tuple[bool, str]:
        try:
            if not self._validate_cidr(ip_cidr) and not self._validate_ip(ip_cidr):
                return False, f"Formato inválido: {ip_cidr}"
            acls = self._parse_acl_file()
            if acl_name not in acls:
                acls[acl_name] = []
            if ip_cidr in acls[acl_name]:
                return False, f"IP/CIDR {ip_cidr} já existe na ACL {acl_name}"
            if 'none' in acls[acl_name]:
                acls[acl_name].remove('none')
            acls[acl_name].append(ip_cidr)
            self._write_acl_file(acls)
            if self._reload_bind():
                self._log_action('add_ip', {
                    'acl': acl_name, 
                    'ip': ip_cidr
                })
                return True, f"IP/CIDR {ip_cidr} adicionado à ACL {acl_name}"
            else:
                return False, "Erro ao recarregar BIND9"
        except Exception as e:
            self._log_action('add_ip', {
                'acl': acl_name, 
                'ip': ip_cidr,
                'error': str(e)
            }, success=False)
            return False, f"Erro ao adicionar IP: {e}"
    def remove_ip_from_acl(self, acl_name: str, ip_cidr: str) -> Tuple[bool, str]:
        try:
            acls = self._parse_acl_file()
            if acl_name not in acls:
                return False, f"ACL {acl_name} não encontrada"
            if ip_cidr not in acls[acl_name]:
                return False, f"IP/CIDR {ip_cidr} não encontrado na ACL {acl_name}"
            acls[acl_name].remove(ip_cidr)
            if not acls[acl_name]:
                acls[acl_name] = ['none']
            self._write_acl_file(acls)
            if self._reload_bind():
                self._log_action('remove_ip', {
                    'acl': acl_name, 
                    'ip': ip_cidr
                })
                return True, f"IP/CIDR {ip_cidr} removido da ACL {acl_name}"
            else:
                return False, "Erro ao recarregar BIND9"
        except Exception as e:
            self._log_action('remove_ip', {
                'acl': acl_name, 
                'ip': ip_cidr,
                'error': str(e)
            }, success=False)
            return False, f"Erro ao remover IP: {e}"
    def create_acl(self, acl_name: str, ips: List[str] = None) -> Tuple[bool, str]:
        try:
            if not acl_name or not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', acl_name):
                return False, "Nome da ACL deve começar com letra e conter apenas letras, números, _ ou -"
            acls = self._parse_acl_file()
            if acl_name in acls:
                return False, f"ACL {acl_name} já existe"
            if ips:
                for ip in ips:
                    if not self._validate_cidr(ip) and not self._validate_ip(ip):
                        return False, f"Formato inválido: {ip}"
            acls[acl_name] = ips if ips else ['none']
            self._write_acl_file(acls)
            if self._reload_bind():
                self._log_action('create_acl', {
                    'name': acl_name, 
                    'ips': ips or []
                })
                return True, f"ACL {acl_name} criada com sucesso"
            else:
                return False, "Erro ao recarregar BIND9"
        except Exception as e:
            self._log_action('create_acl', {
                'name': acl_name,
                'error': str(e)
            }, success=False)
            return False, f"Erro ao criar ACL: {e}"
    def delete_acl(self, acl_name: str) -> Tuple[bool, str]:
        try:
            protected_acls = ['trusted', 'blackhole']
            if acl_name in protected_acls:
                return False, f"ACL {acl_name} está protegida e não pode ser removida"
            acls = self._parse_acl_file()
            if acl_name not in acls:
                return False, f"ACL {acl_name} não encontrada"
            del acls[acl_name]
            self._write_acl_file(acls)
            if self._reload_bind():
                self._log_action('delete_acl', {'name': acl_name})
                return True, f"ACL {acl_name} removida com sucesso"
            else:
                return False, "Erro ao recarregar BIND9"
        except Exception as e:
            self._log_action('delete_acl', {
                'name': acl_name,
                'error': str(e)
            }, success=False)
            return False, f"Erro ao remover ACL: {e}"
    def get_statistics(self) -> Dict:
        try:
            acls = self._parse_acl_file()
            stats = {
                'total_acls': len(acls),
                'total_entries': sum(len(ips) for ips in acls.values()),
                'acls': {}
            }
            for acl_name, ips in acls.items():
                stats['acls'][acl_name] = {
                    'count': len(ips),
                    'has_none': 'none' in ips,
                    'entries': len([ip for ip in ips if ip != 'none'])
                }
            return stats
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas ACL: {e}")
            return {'error': str(e)}
    def restore_backup(self, backup_file: str) -> Tuple[bool, str]:
        try:
            if not os.path.exists(backup_file):
                return False, "Arquivo de backup não encontrado"
            current_backup = self._backup_config()
            shutil.copy2(backup_file, self.acl_file)
            if self._test_bind_config():
                if self._reload_bind():
                    self._log_action('restore_backup', {'file': backup_file})
                    return True, f"Backup restaurado com sucesso"
                else:
                    return False, "Erro ao recarregar BIND9 após restauração"
            else:
                shutil.copy2(current_backup, self.acl_file)
                return False, "Backup contém configuração inválida"
        except Exception as e:
            self._log_action('restore_backup', {
                'file': backup_file,
                'error': str(e)
            }, success=False)
            return False, f"Erro ao restaurar backup: {e}"
acl_manager = ACLManager()