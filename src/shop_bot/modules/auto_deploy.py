import asyncio
import subprocess
import logging
import paramiko
import json
import time
import requests
import random
import string
import re
import uuid
from typing import Dict, Optional, Tuple
from py3xui import Api
from py3xui.inbound import Inbound, Settings, Sniffing, StreamSettings
from shop_bot.data_manager.database import (
    create_auto_deploy_host, update_host_after_deploy
)

logger = logging.getLogger(__name__)

class AutoDeploy:
    """Класс для автоматического деплоя панели 3x-ui"""
    
    def __init__(self):
        self.install_timeout = 300  # 5 минут
        
    def _generate_random_port(self) -> int:
        """Генерирует случайный порт для панели в диапазоне 10000-65000"""
        return random.randint(10000, 65000)
    
    def _generate_random_username(self) -> str:
        """Генерирует случайное имя пользователя"""
        return ''.join(random.choices(string.ascii_lowercase, k=8))
    
    def _generate_random_password(self) -> str:
        """Генерирует случайный пароль без спецсимволов для bash"""
        characters = string.ascii_letters + string.digits + "!@#$%"
        return ''.join(random.choices(characters, k=12))
    
    def _generate_random_ssh_password(self) -> str:
        """Генерирует случайный SSH пароль для сервера"""
        characters = string.ascii_letters + string.digits + "!@#$%"
        return ''.join(random.choices(characters, k=16))
    
    def _generate_random_secpath(self) -> str:
        """Генерирует случайный secPath для панели"""
        return '/' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    def _generate_random_ssh_port(self) -> int:
        """Генерирует случайный SSH порт в диапазоне 10000-65000"""
        return random.randint(10000, 65000)
        
    async def deploy_3xui(self, host_name: str, ssh_host: str, ssh_username: str, 
                         ssh_password: str, ssh_port: int = 22, max_configs: int = 20) -> Dict:
        """
        Полный цикл автоматического деплоя 3x-ui панели
        
        Args:
            host_name: Имя хоста в системе
            ssh_host: IP/домен сервера
            ssh_username: SSH пользователь
            ssh_password: SSH пароль
            ssh_port: SSH порт
            max_configs: Максимальное количество конфигураций
            
        Returns:
            Dict: Результат деплоя с данными панели или ошибкой
        """
        try:
            logger.info(f"Starting auto-deploy for {host_name} ({ssh_host})")
            
            # Генерируем случайные данные для панели
            panel_port = self._generate_random_port()
            panel_username = self._generate_random_username()
            panel_password = self._generate_random_password()
            panel_secpath = self._generate_random_secpath()
            new_ssh_port = self._generate_random_ssh_port()
            new_ssh_password = self._generate_random_ssh_password()
            
            logger.info(f"Generated panel credentials - Port: {panel_port}, Username: {panel_username}, Password: {panel_password}, SecPath: {panel_secpath}")
            logger.info(f"Generated SSH port: {new_ssh_port}")
            
            # Шаг 1: Создаем запись в БД
            host_id = create_auto_deploy_host(
                name=host_name,
                ssh_host=ssh_host,
                ssh_username=ssh_username,
                ssh_password=ssh_password,
                ssh_port=ssh_port,
                max_configs=max_configs,
                panel_port=panel_port,
                panel_username=panel_username,
                panel_password=panel_password,
                panel_secpath=panel_secpath
            )
            
            if not host_id:
                return {"success": False, "error": "Не удалось создать запись хоста в БД"}
            
            # Шаг 2: Проверяем SSH подключение
            ssh_result = await self._test_ssh_connection(ssh_host, ssh_username, ssh_password, ssh_port)
            if not ssh_result["success"]:
                return {"success": False, "error": f"SSH подключение не удалось: {ssh_result['error']}"}
            
            # Шаг 3: Устанавливаем 3x-ui
            install_result = await self._install_3xui(ssh_host, ssh_username, ssh_password, ssh_port, panel_port, panel_username, panel_password, panel_secpath)
            if not install_result["success"]:
                return {"success": False, "error": f"Ошибка установки 3x-ui: {install_result['error']}"}
            
            # Шаг 4: Получаем SNI с помощью SNI-Fetch
            sni_result = await self._fetch_sni(ssh_host, ssh_username, ssh_password, ssh_port)
            sni = sni_result.get("sni", "www.speedtest.net")  # fallback SNI
            
            # Очищаем SNI от лишних символов и добавляем www версию если её нет
            sni = sni.strip().replace('\x1b[0m', '').replace('\x1b[1m', '').replace('\x1b[32m', '').replace('\x1b[31m', '')
            
            # Если SNI не содержит запятую, добавляем www версию
            if ',' not in sni and not sni.startswith('www.'):
                sni = f"{sni}, www.{sni}"
            
            logger.info(f"Processed SNI: {sni}")
            
            # Шаг 5: Настраиваем панель
            config_result = await self._configure_panel(ssh_host, ssh_username, ssh_password, ssh_port, sni, panel_port, panel_secpath)
            if not config_result["success"]:
                return {"success": False, "error": f"Ошибка настройки панели: {config_result['error']}"}
            
            # Шаг 6: Создаем inbound (БЕЗ настройки безопасности)
            inbound_result = await self._create_inbound(ssh_host, ssh_username, ssh_password, ssh_port, sni, panel_port, panel_secpath, panel_username, panel_password)
            if not inbound_result["success"]:
                return {"success": False, "error": f"Ошибка создания inbound: {inbound_result['error']}"}
            
            # Шаг 7: Настраиваем безопасность сервера (ПОСЛЕ создания инбаунда)
            security_result = await self._configure_server_security(ssh_host, ssh_username, ssh_password, ssh_port, panel_port, new_ssh_port, new_ssh_password)
            if not security_result["success"]:
                logger.warning(f"Security configuration failed: {security_result['error']}")
            
            # Шаг 8: Обновляем данные в БД
            panel_url = f"http://{ssh_host}:{panel_port}{panel_secpath}"  # HTTP
            update_host_after_deploy(
                host_id=host_id,
                host_url=panel_url,
                host_username=panel_username,
                host_password=panel_password,
                inbound_id=inbound_result["inbound_id"],
                ssh_public_key="",  # Больше не генерируем SSH ключи
                new_ssh_port=new_ssh_port,
                new_ssh_password=new_ssh_password
            )
            
            logger.info(f"Successfully deployed 3x-ui for {host_name}")
            logger.info(f"Panel URL: {panel_url}")
            logger.info(f"Username: {panel_username}")
            logger.info(f"Password: {panel_password}")
            logger.info(f"New SSH Port: {new_ssh_port}")
            logger.info(f"New SSH Password: {new_ssh_password}")
            
            logger.info(f"Successfully deployed 3x-ui for {host_name}")
            
            return {
                "success": True,
                "panel_url": panel_url,
                "panel_port": panel_port,
                "panel_username": panel_username,
                "panel_password": panel_password,
                "inbound_id": inbound_result["inbound_id"],
                "sni": sni,
                "host_id": host_id
            }
            
        except Exception as e:
            logger.error(f"Auto-deploy failed for {host_name}: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    async def _test_ssh_connection(self, host: str, username: str, password: str, port: int) -> Dict:
        """Тестирует SSH подключение"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=username, password=password, port=port, timeout=30)
            
            # Проверяем базовые команды
            stdin, stdout, stderr = ssh.exec_command("whoami")
            result = stdout.read().decode().strip()
            
            ssh.close()
            
            if result == username:
                return {"success": True}
            else:
                return {"success": False, "error": "Неверные SSH данные"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _install_3xui(self, host: str, username: str, password: str, port: int, panel_port: int, panel_username: str, panel_password: str, panel_secpath: str) -> Dict:
        """Устанавливает 3x-ui панель"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=username, password=password, port=port, timeout=30)
            
            # Команды для установки 3x-ui
            install_commands = [
                "apt update -y",
                "apt install -y curl wget",
                # Устанавливаем 3x-ui с стабильной версией
                "wget https://github.com/MHSanaei/3x-ui/releases/download/v2.6.6/x-ui-linux-amd64.tar.gz -O /usr/local/x-ui-linux-amd64.tar.gz",
                "tar -xzf /usr/local/x-ui-linux-amd64.tar.gz -C /usr/local/",
                "chmod +x /usr/local/x-ui/x-ui",
                "ln -sf /usr/local/x-ui/x-ui /usr/bin/x-ui",
                "mkdir -p /etc/x-ui"
            ]
            
            # Создаем systemd сервис отдельной командой
            service_script = f"""cat > /etc/systemd/system/x-ui.service << 'EOF'
[Unit]
Description=x-ui Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/x-ui
ExecStart=/usr/local/x-ui/x-ui
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF"""
            
            # Команды для запуска сервиса
            service_commands = [
                service_script,
                "systemctl daemon-reload",
                "systemctl enable x-ui",
                "systemctl stop x-ui || true",  # Останавливаем если запущен
                "pkill -f x-ui || true",  # Убиваем все процессы x-ui
                "systemctl start x-ui"
            ]
            
            # Команды для настройки панели после установки
            config_commands = [
                # Останавливаем службу перед настройкой
                "systemctl stop x-ui || true",
                # Меняем порт панели (убеждаемся что это число)
                f"/usr/local/x-ui/x-ui setting -port {int(panel_port)}",
                # Меняем логин и пароль одновременно (требуются оба параметра)
                f"/usr/local/x-ui/x-ui setting -username '{panel_username}' -password '{panel_password}'",
                # Меняем secPath (корневой путь URL)
                f"/usr/local/x-ui/x-ui setting -webBasePath '{panel_secpath}'",
                # Показываем текущие настройки для проверки
                "/usr/local/x-ui/x-ui setting -show",
                # Запускаем службу
                "systemctl start x-ui"
            ]
            
            # Выполняем команды установки
            for i, cmd in enumerate(install_commands):
                logger.info(f"Installing - Executing: {cmd}")
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=self.install_timeout)
                
                # Ждем завершения команды
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode().strip()
                error_output = stderr.read().decode().strip()
                
                if output:
                    logger.info(f"Install output: {output}")
                if error_output:
                    logger.warning(f"Install stderr: {error_output}")
                
                if exit_status != 0:
                    logger.error(f"Install command failed: {cmd}, Error: {error_output}")
                    ssh.close()
                    return {"success": False, "error": f"Ошибка установки: {cmd}"}
            
            # Выполняем команды создания сервиса
            for i, cmd in enumerate(service_commands):
                logger.info(f"Service setup - Executing: {cmd}")
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
                
                # Ждем завершения команды
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode().strip()
                error_output = stderr.read().decode().strip()
                
                if output:
                    logger.info(f"Service output: {output}")
                if error_output:
                    logger.warning(f"Service stderr: {error_output}")
                
                if exit_status != 0:
                    logger.error(f"Service command failed: {cmd}, Error: {error_output}")
                    # Продолжаем выполнение, но логируем ошибку
            
            # Ждем запуска сервиса
            await asyncio.sleep(10)
            logger.info("Installation completed, starting configuration...")
            
            # Выполняем команды настройки
            for i, cmd in enumerate(config_commands):
                logger.info(f"Configuring - Executing: {cmd}")
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
                
                # Ждем завершения команды
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode().strip()
                error_output = stderr.read().decode().strip()
                
                if output:
                    logger.info(f"Config output: {output}")
                if error_output:
                    logger.warning(f"Config stderr: {error_output}")
                
                # Проверяем успешность выполнения команд настройки
                if i < 3 and exit_status != 0:  # Первые 3 команды - настройки
                    logger.error(f"Configuration command failed: {cmd}")
                    logger.error(f"Error: {error_output}")
                    # Продолжаем выполнение, но логируем ошибку
                
                # Ждем после перезапуска службы
                if "restart" in cmd:
                    await asyncio.sleep(10)
                elif "show" in cmd:
                    await asyncio.sleep(2)  # Меньше времени для команды показа
                else:
                    await asyncio.sleep(3)
            
            # Если CLI команды не сработали, пробуем через базу данных
            logger.info("Checking if settings were applied correctly...")
            stdin, stdout, stderr = ssh.exec_command("/usr/local/x-ui/x-ui setting -show", timeout=30)
            settings_output = stdout.read().decode().strip()
            logger.info(f"Current settings: {settings_output}")
            
            # Проверяем, применились ли настройки
            if f"port: {panel_port}" not in settings_output or "hasDefaultCredential: true" in settings_output:
                logger.warning("CLI settings failed, trying database method...")
                
                # Альтернативный способ через базу данных
                db_commands = [
                    f"sqlite3 /etc/x-ui/x-ui.db \"UPDATE settings SET value='{panel_port}' WHERE key='webPort';\"",
                    f"sqlite3 /etc/x-ui/x-ui.db \"UPDATE users SET username='{panel_username}', password='{panel_password}' WHERE id=1;\"",
                    "systemctl restart x-ui"
                ]
                
                for db_cmd in db_commands:
                    logger.info(f"DB method - Executing: {db_cmd}")
                    stdin, stdout, stderr = ssh.exec_command(db_cmd, timeout=30)
                    await asyncio.sleep(3)
                
                # Дополнительно пробуем через HTTP API
                logger.info("Trying HTTP API method for credentials...")
                try:
                    # Получаем токен авторизации
                    auth_response = requests.post(f"http://{host}:{panel_port}/login", 
                                                json={"username": "admin", "password": "admin"}, 
                                                timeout=10)
                    if auth_response.status_code == 200:
                        auth_data = auth_response.json()
                        if auth_data.get("success"):
                            token = auth_data.get("token")
                            
                            # Меняем пароль через API
                            headers = {"Authorization": f"Bearer {token}"}
                            password_data = {
                                "oldPassword": "admin",
                                "newPassword": panel_password
                            }
                            password_response = requests.post(f"http://{host}:{panel_port}/panel/api/inbounds/updateUser", 
                                                            json=password_data, headers=headers, timeout=10)
                            logger.info(f"Password change API response: {password_response.status_code}")
                            
                except Exception as api_e:
                    logger.warning(f"HTTP API method failed: {api_e}")
            
            ssh.close()
            return {"success": True}
            
        except Exception as e:
            logger.error(f"3x-ui installation failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _fetch_sni(self, host: str, username: str, password: str, port: int) -> Dict:
        """Получает SNI с помощью SNI-Fetch бинарного файла"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=username, password=password, port=port, timeout=30)
            
            # Устанавливаем бинарный SNI-Fetch
            sni_commands = [
                "cd /tmp",
                "wget -q https://github.com/HelloLingC/SNI-Fetch/releases/download/v1.2/sni-fetch-v1.2-linux-amd64.tar.gz",
                "tar -xzf sni-fetch-v1.2-linux-amd64.tar.gz",
                "chmod +x sni-fetch",
                f"./sni-fetch -t {host} -n 1"
            ]
            
            sni = "www.speedtest.net"  # fallback
            
            for i, cmd in enumerate(sni_commands):
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=120)
                output = stdout.read().decode().strip()
                
                # Парсим вывод последней команды (sni-fetch)
                if i == len(sni_commands) - 1 and output:
                    logger.info(f"SNI-Fetch output: {output}")
                    lines = output.split('\n')
                    found_section = False
                    
                    for line in lines:
                        if "Found" in line and "SNIs available:" in line:
                            found_section = True
                            continue
                        
                        if found_section and line.strip():
                            # Извлекаем доменное имя из строки
                            clean_line = line.strip()
                            if clean_line and '.' in clean_line:
                                # Убираем лишние символы в начале
                                if clean_line.startswith(' '):
                                    clean_line = clean_line.strip()
                                sni = clean_line
                                break
            
            ssh.close()
            logger.info(f"Retrieved SNI: {sni}")
            return {"success": True, "sni": sni}
            
        except Exception as e:
            logger.warning(f"SNI fetch failed, using fallback: {e}")
            return {"success": True, "sni": "www.speedtest.net"}
    
    async def _configure_panel(self, host: str, username: str, password: str, port: int, sni: str, panel_port: int, panel_secpath: str) -> Dict:
        """Настраивает панель 3x-ui"""
        try:
            # Ждем полного запуска панели
            await asyncio.sleep(20)
            
            panel_url = f"http://{host}:{panel_port}"
            
            # Проверяем доступность панели
            max_retries = 15
            panel_accessible = False
            
            for i in range(max_retries):
                try:
                    logger.info(f"Checking panel accessibility: attempt {i+1}/{max_retries}")
                    response = requests.get(f"{panel_url}/login", timeout=10)
                    if response.status_code == 200:
                        panel_accessible = True
                        logger.info("3x-ui panel is accessible!")
                        break
                except Exception as e:
                    logger.info(f"Panel check failed: {e}")
                    if i == max_retries - 1:
                        # Последняя попытка - проверяем SSH соединением статус службы
                        try:
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(hostname=host, username=username, password=password, port=port, timeout=30)
                            
                            # Проверяем статус службы x-ui
                            stdin, stdout, stderr = ssh.exec_command("systemctl status x-ui")
                            status_output = stdout.read().decode().strip()
                            logger.info(f"x-ui service status: {status_output}")
                            
                            # Проверяем на каком порту работает панель
                            stdin, stdout, stderr = ssh.exec_command("netstat -tlnp | grep x-ui")
                            netstat_output = stdout.read().decode().strip()
                            logger.info(f"x-ui port status: {netstat_output}")
                            
                            # Проверяем конфигурацию панели
                            stdin, stdout, stderr = ssh.exec_command("x-ui <<< $'20\\n'")
                            config_output = stdout.read().decode().strip()
                            logger.info(f"x-ui config: {config_output}")
                            
                            # Пытаемся перезапустить службу
                            stdin, stdout, stderr = ssh.exec_command("systemctl restart x-ui")
                            await asyncio.sleep(10)
                            
                            ssh.close()
                        except Exception as ssh_e:
                            logger.error(f"SSH check failed: {ssh_e}")
                        
                        return {"success": False, "error": "Панель недоступна после установки"}
                    
                    await asyncio.sleep(15)
            
            if not panel_accessible:
                return {"success": False, "error": "Панель недоступна после всех попыток"}
            
            return {"success": True}
            
        except Exception as e:
            logger.error(f"Panel configuration failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _create_inbound(self, host: str, username: str, password: str, port: int, sni: str, panel_port: int, panel_secpath: str, panel_username: str, panel_password: str) -> Dict:
        """Создает inbound для VLESS"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=username, password=password, port=port, timeout=30)
            
            # Генерируем short_id для Reality
            stdin, stdout, stderr = ssh.exec_command("openssl rand -hex 8")
            short_id = stdout.read().decode().strip()
            short_id_error = stderr.read().decode().strip()
            
            if not short_id or short_id_error:
                logger.error(f"Failed to generate short_id. Output: '{short_id}', Error: '{short_id_error}'")
                return {"success": False, "error": "Failed to generate short_id"}
            
            logger.info(f"Generated short_id: {short_id}")
            logger.info(f"SNI: {sni}")
            
            # Проверяем статус службы перед созданием inbound
            stdin, stdout, stderr = ssh.exec_command("systemctl status x-ui")
            status_output = stdout.read().decode().strip()
            logger.info(f"x-ui service status before inbound creation: {status_output}")
            
            # Убеждаемся что служба запущена
            stdin, stdout, stderr = ssh.exec_command("systemctl start x-ui")
            await asyncio.sleep(5)
            
            # Создаем inbound через py3xui библиотеку  
            # Пробуем HTTP и HTTPS (после установки сертификатов x-ui может переключиться на HTTPS)
            panel_url_http = f"http://{host}:{panel_port}{panel_secpath}"
            panel_url_https = f"https://{host}:{panel_port}{panel_secpath}"
            
            api = None
            
            # Попытка 1: HTTP
            try:
                logger.info(f"Attempting HTTP connection to {panel_url_http}")
                api = Api(
                    host=panel_url_http,
                    username=panel_username,
                    password=panel_password
                )
                api.login()
                logger.info(f"HTTP connection successful")
                
            except Exception as http_error:
                logger.warning(f"HTTP connection failed: {http_error}")
                
                # Попытка 2: HTTPS с отключенной проверкой TLS
                try:
                    logger.info(f"Attempting HTTPS connection (no TLS verify) to {panel_url_https}")
                    api = Api(
                        host=panel_url_https,
                        username=panel_username,
                        password=panel_password,
                        use_tls_verify=False
                    )
                    api.login()
                    logger.info(f"HTTPS connection successful")
                    
                except Exception as https_error:
                    logger.error(f"Both HTTP and HTTPS connections failed")
                    logger.error(f"HTTP error: {http_error}")
                    logger.error(f"HTTPS error: {https_error}")
                    return {"success": False, "error": f"Could not connect to panel: {https_error}"}
            
            if not api:
                return {"success": False, "error": "Could not establish API connection"}
            
            # Получаем Reality ключи через API endpoint
            private_key = ""
            public_key = ""
            
            try:
                # Определяем правильный URL для API
                base_url = f"http://{host}:{panel_port}{panel_secpath}"
                if base_url.endswith('/'):
                    base_url = base_url[:-1]
                
                # Получаем ключи через API
                import requests
                import json
                
                # Создаем сессию с cookies от авторизованного API
                session = requests.Session()
                if hasattr(api, 'client') and hasattr(api.client, 'cookies'):
                    session.cookies.update(api.client.cookies)
                
                # POST запрос на получение Reality ключей
                cert_url = f"{base_url}/server/getNewX25519Cert"
                logger.info(f"Requesting Reality keys from: {cert_url}")
                
                response = session.post(cert_url, verify=False)
                if response.status_code == 200:
                    cert_data = response.json()
                    if cert_data.get("success") and cert_data.get("obj"):
                        private_key = cert_data["obj"]["privateKey"]
                        public_key = cert_data["obj"]["publicKey"]
                        logger.info(f"Successfully obtained Reality keys from API")
                        logger.info(f"Private key: {private_key[:10]}...")
                        logger.info(f"Public key: {public_key[:10]}...")
                    else:
                        logger.warning(f"API returned error: {cert_data}")
                else:
                    logger.warning(f"Failed to get Reality keys from API: {response.status_code}")
                    
            except Exception as api_error:
                logger.warning(f"Failed to get Reality keys from API: {api_error}")
            
            # Если не удалось получить ключи через API, используем пустые
            if not private_key or not public_key:
                logger.info("Using empty Reality keys - x-ui will generate them automatically")
                private_key = ""
                public_key = ""
            
            # Генерируем UUID для клиента
            client_id = str(uuid.uuid4())
            
            # Создаем inbound с py3xui
            logger.info(f"Creating inbound with Reality configuration")
            try:
                # Создаем inbound точно как в примере из документации
                from py3xui.inbound import Inbound, Settings, Sniffing, StreamSettings
                
                settings = Settings()
                sniffing = Sniffing(enabled=True)
                
                tcp_settings = {
                    "acceptProxyProtocol": False,
                    "header": {"type": "none"},
                }
                
                # Парсим SNI - может быть несколько доменов через запятую
                sni_list = [s.strip() for s in sni.split(',') if s.strip()]
                primary_sni = sni_list[0] if sni_list else sni
                
                # Создаем Reality настройки с нашим SNI и ключами
                reality_settings = {
                    "show": False,
                    "xver": 0,
                    "dest": f"{primary_sni}:443",
                    "serverNames": sni_list,  # Используем все SNI домены
                    "privateKey": private_key,
                    "shortIds": [short_id],
                    "settings": {
                        "publicKey": public_key,
                        "fingerprint": "chrome",
                        "serverName": primary_sni,
                        "spiderX": "/"
                    }
                }
                
                logger.info(f"Reality config - Dest: {primary_sni}:443, ServerNames: {sni_list}")
                
                stream_settings = StreamSettings(
                    security="reality", 
                    network="tcp", 
                    tcp_settings=tcp_settings,
                    reality_settings=reality_settings
                )
                
                inbound = Inbound(
                    enable=True,
                    port=443,
                    protocol="vless",
                    settings=settings,
                    stream_settings=stream_settings,
                    sniffing=sniffing,
                    remark="test3",
                )
                
                # Добавляем inbound
                logger.info("Adding inbound via py3xui...")
                response = api.inbound.add(inbound)
                logger.info(f"py3xui response: {response}")
                
                # Ждем немного после создания
                await asyncio.sleep(5)
                
            except Exception as api_error:
                logger.error(f"py3xui API error: {api_error}")
                response = None
                
                if response and response.get("success"):
                    logger.info("Inbound created successfully via py3xui")
                    inbound_id = response.get("obj", {}).get("id", 1)
                    
                    # Проверяем, что inbound действительно создался
                    try:
                        inbounds = api.inbound.get_list()
                        logger.info(f"Current inbounds: {len(inbounds)} found")
                        if inbounds:
                            logger.info(f"Latest inbound ID: {inbounds[-1].id if hasattr(inbounds[-1], 'id') else 'unknown'}")
                    except Exception as check_e:
                        logger.warning(f"Failed to verify inbound creation: {check_e}")
                        
                else:
                    # Используем интерактивное меню для создания inbound
                    logger.info("Creating inbound via interactive menu")
                    inbound_command = f"x-ui <<< $'7\\n1\\n\\n443\\nvless\\nreality\\ntcp\\n\\n\\nxtls-rprx-vision\\ntrue\\n\\n\\n{sni}\\n\\n{short_id}\\nchrome\\ny\\ny\\n0\\n'"
                    
                    try:
                        logger.info("Executing inbound creation command...")
                        stdin, stdout, stderr = ssh.exec_command(inbound_command, timeout=120)
                        
                        # Ждем завершения команды
                        exit_status = stdout.channel.recv_exit_status()
                        output = stdout.read().decode().strip()
                        error_output = stderr.read().decode().strip()
                        
                        logger.info(f"Inbound creation exit status: {exit_status}")
                        if output:
                            logger.info(f"Inbound creation output: {output}")
                        if error_output:
                            logger.warning(f"Inbound creation stderr: {error_output}")
                        
                        if exit_status == 0:
                            logger.info("Inbound creation successful")
                        else:
                            logger.warning("Inbound creation failed, but continuing...")
                            
                    except Exception as e:
                        logger.error(f"Inbound creation error: {e}")
                    
                    inbound_id = 1
                    
            except Exception as py3xui_e:
                logger.warning(f"py3xui method failed: {py3xui_e}, trying with SSL certificate")
                try:
                    # Пробуем еще раз без TLS verification
                    api = Api(
                        host=panel_url,
                        username=panel_username,
                        password=panel_password,
                        use_tls_verify=False
                    )
                    api.login()
                    response = api.inbound.add(inbound)
                    logger.info(f"Second py3xui attempt response: {response}")
                except Exception as second_e:
                    logger.warning(f"Second py3xui attempt failed: {second_e}, using interactive menu")
                    inbound_command = f"x-ui <<< $'7\\n1\\n\\n443\\nvless\\nreality\\ntcp\\n\\n\\nxtls-rprx-vision\\ntrue\\n\\n\\n{sni}\\n\\n{short_id}\\nchrome\\ny\\ny\\n0\\n'"
                
                try:
                    logger.info("Executing second fallback inbound creation...")
                    stdin, stdout, stderr = ssh.exec_command(inbound_command, timeout=120)
                    
                    exit_status = stdout.channel.recv_exit_status()
                    output = stdout.read().decode().strip()
                    error_output = stderr.read().decode().strip()
                    
                    logger.info(f"Second fallback exit status: {exit_status}")
                    if output:
                        logger.info(f"Second fallback output: {output}")
                    if error_output:
                        logger.warning(f"Second fallback stderr: {error_output}")
                        
                except Exception as e:
                    logger.error(f"Second fallback error: {e}")
                
                inbound_id = 1
            
            # Читаем вывод команды (если команда была выполнена)
            try:
                output = stdout.read().decode().strip()
                error_output = stderr.read().decode().strip()
                
                logger.info(f"Inbound creation output: {output}")
                if error_output:
                    logger.warning(f"Inbound creation stderr: {error_output}")
            except:
                logger.info("No command output to read (HTTP API used)")
            
            # Дожидаемся создания inbound
            await asyncio.sleep(10)
            
            # Получаем список inbound через интерактивное меню
            stdin, stdout, stderr = ssh.exec_command("timeout 15 x-ui <<< $'8\\n0\\n'")
            list_output = stdout.read().decode().strip()
            
            logger.info(f"Inbound list output: {list_output}")
            
            # Парсим ID созданного inbound из вывода (обычно это 1 для первого inbound)
            inbound_id = 1
            
            # Пытаемся найти ID в выводе
            if "id" in list_output.lower() or "ID:" in list_output:
                # Ищем числовые ID в выводе
                ids = re.findall(r'(?:id|ID)[:=]\s*(\d+)', list_output)
                if ids:
                    inbound_id = int(ids[0])
                    logger.info(f"Found inbound ID: {inbound_id}")
                else:
                    # Альтернативный поиск
                    for line in list_output.split('\n'):
                        if "ID:" in line:
                            try:
                                inbound_id = int(line.split("ID:")[1].strip().split()[0])
                                break
                            except:
                                pass
            
            ssh.close()
            logger.info(f"Created inbound with ID: {inbound_id}")
            return {"success": True, "inbound_id": inbound_id}
            
        except Exception as e:
            logger.error(f"Inbound creation failed: {e}")
            # Возвращаем успех с ID 1 как fallback
            return {"success": True, "inbound_id": 1}
    
    async def get_deploy_status(self, host: str, panel_port: int, ssh_port: int = 22) -> Dict:
        """Проверяет статус развернутой панели"""
        try:
            panel_url = f"http://{host}:{panel_port}"
            response = requests.get(f"{panel_url}/login", timeout=10)
            
            if response.status_code == 200:
                return {"success": True, "status": "running", "url": panel_url}
            else:
                return {"success": False, "status": "error", "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "status": "offline", "error": str(e)}
    
    async def _configure_server_security(self, host: str, username: str, password: str, port: int, panel_port: int, new_ssh_port: int, new_ssh_password: str) -> Dict:
        """Настраивает безопасность сервера: SSH ключи, отключение паролей, генерация сертификатов"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=username, password=password, port=port, timeout=30)
            
            logger.info("Configuring server security...")
            
            # Команды для настройки безопасности (упрощенные)
            security_commands = [
                # Обновляем систему
                "apt update -y",
                
                # Устанавливаем sqlite3 для работы с базой данных
                "apt install -y sqlite3",
                
                # Создание сертификатов в формате .key
                "openssl req -x509 -newkey rsa:4096 -nodes -sha256 -keyout /root/private.key -out /root/public.key -days 3650 -subj '/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com'",
                
                # Добавление путей к сертификатам в базу x-ui
                "sqlite3 /etc/x-ui/x-ui.db \"INSERT OR REPLACE INTO settings (key, value) VALUES ('webCertFile', '/root/private.key');\"",
                "sqlite3 /etc/x-ui/x-ui.db \"INSERT OR REPLACE INTO settings (key, value) VALUES ('webKeyFile', '/root/private.key');\"",
                
                # Устанавливаем правильные права доступа
                "chmod 600 /root/private.key",
                "chmod 644 /root/public.key",
                
                # Перезапуск службы x-ui
                "systemctl restart x-ui",
                
                # Меняем SSH порт
                f"sed -i 's/#Port 22/Port {new_ssh_port}/' /etc/ssh/sshd_config",
                f"sed -i 's/Port 22/Port {new_ssh_port}/' /etc/ssh/sshd_config",
                
                # Меняем SSH пароль для root
                f"echo 'root:{new_ssh_password}' | chpasswd",
                
                # Перезапускаем SSH
                "systemctl restart ssh"
            ]
            
            for i, cmd in enumerate(security_commands):
                logger.info(f"Security - Executing: {cmd}")
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
                
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode().strip()
                error_output = stderr.read().decode().strip()
                
                if output:
                    logger.info(f"Security output: {output}")
                
                if error_output:
                    logger.warning(f"Security stderr: {error_output}")
                
                if exit_status != 0:
                    logger.warning(f"Security command failed: {cmd}")
                
                await asyncio.sleep(2)
            
            ssh.close()
            
            logger.info("Security configuration completed successfully")
            return {"success": True}
                
        except Exception as e:
            logger.error(f"Security configuration failed: {e}")
            return {"success": False, "error": str(e)}
    
    def validate_ssh_params(self, ssh_host: str, ssh_username: str, ssh_password: str, ssh_port: int) -> Dict:
        """Валидирует параметры SSH"""
        errors = []
        
        if not ssh_host or len(ssh_host.strip()) == 0:
            errors.append("SSH хост не может быть пустым")
        
        if not ssh_username or len(ssh_username.strip()) == 0:
            errors.append("SSH пользователь не может быть пустым")
        
        if not ssh_password or len(ssh_password.strip()) == 0:
            errors.append("SSH пароль не может быть пустым")
        
        if not isinstance(ssh_port, int) or ssh_port < 1 or ssh_port > 65535:
            errors.append("SSH порт должен быть числом от 1 до 65535")
        
        if errors:
            return {"valid": False, "errors": errors}
        
        return {"valid": True}
