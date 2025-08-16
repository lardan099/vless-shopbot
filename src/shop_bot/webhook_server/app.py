import os
import logging
import asyncio
import json
import hashlib
import base64
import threading
import time
import uuid
from hmac import compare_digest
from datetime import datetime, timedelta
from functools import wraps
from math import ceil
from flask import Flask, request, render_template, redirect, url_for, flash, session, current_app, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from shop_bot.modules import xui_api
from shop_bot.modules.auto_deploy import AutoDeploy
from shop_bot.modules.load_balancer import LoadBalancer
from shop_bot.bot import handlers 
from shop_bot.data_manager.database import (
    get_all_settings, update_setting, get_all_hosts, get_plans_for_host,
    create_host, delete_host, create_plan, delete_plan, get_user_count,
    get_total_keys_count, get_total_spent_sum, get_daily_stats_for_charts,
    get_recent_transactions, get_paginated_transactions, get_all_users, get_user_keys,
    ban_user, unban_user, delete_user_keys, get_setting, find_and_complete_ton_transaction,
    get_hosts_load_status, update_host_limits
)

def check_server_conflicts(host_name, ssh_host, exclude_session_id=None):
    """
    Проверяет конфликты серверов с учетом активных сессий деплоя
    """
    conflicts = []
    
    # Проверяем существующие хосты в БД
    existing_hosts = get_all_hosts()
    
    # Проверка имени хоста
    if any(host['host_name'] == host_name for host in existing_hosts):
        conflicts.append(f"Сервер с именем '{host_name}' уже существует в системе")
    
    # Проверка IP/домена
    for host in existing_hosts:
        host_url = host['url'].replace('http://', '').replace('https://', '')
        existing_ip = host_url.split(':')[0]
        if existing_ip == ssh_host:
            conflicts.append(f"Сервер с адресом '{ssh_host}' уже добавлен в систему")
    
    # Проверяем активные сессии деплоя
    with deploy_lock:
        for session_id, session in deploy_sessions.items():
            if exclude_session_id and session_id == exclude_session_id:
                continue
                
            if session.status in ['starting', 'validating', 'connecting', 'installing']:
                if session.host_name == host_name:
                    conflicts.append(f"Сервер с именем '{host_name}' уже развертывается в другой сессии")
                if session.ssh_host == ssh_host:
                    conflicts.append(f"Сервер с адресом '{ssh_host}' уже развертывается в другой сессии")
    
    return conflicts

_bot_controller = None

# Глобальное хранилище статусов деплоя
deploy_sessions = {}
deploy_lock = threading.Lock()

class DeploySession:
    def __init__(self, session_id, host_name, ssh_host):
        self.session_id = session_id
        self.host_name = host_name
        self.ssh_host = ssh_host
        self.status = "starting"
        self.progress = 0
        self.current_step = ""
        self.error = None
        self.result = None
        self.created_at = datetime.now()
        
    def update_status(self, status, progress=None, current_step=None, error=None, result=None):
        self.status = status
        if progress is not None:
            self.progress = progress
        if current_step is not None:
            self.current_step = current_step
        if error is not None:
            self.error = error
        if result is not None:
            self.result = result
            
    def to_dict(self):
        return {
            'session_id': self.session_id,
            'host_name': self.host_name,
            'ssh_host': self.ssh_host,
            'status': self.status,
            'progress': self.progress,
            'current_step': self.current_step,
            'error': self.error,
            'result': self.result,
            'created_at': self.created_at.isoformat()
        }

ALL_SETTINGS_KEYS = [
    "panel_login", "panel_password", "about_text", "terms_url", "privacy_url",
    "support_user", "support_text", "channel_url", "telegram_bot_token",
    "telegram_bot_username", "admin_telegram_id", "yookassa_shop_id",
    "yookassa_secret_key", "sbp_enabled", "receipt_email", "cryptobot_token",
    "heleket_merchant_id", "heleket_api_key", "domain", "referral_percentage",
    "referral_discount", "ton_wallet_address", "tonapi_key", "force_subscription"
]

def create_webhook_app(bot_controller_instance):
    global _bot_controller
    _bot_controller = bot_controller_instance

    app_file_path = os.path.abspath(__file__)
    app_dir = os.path.dirname(app_file_path)
    template_dir = os.path.join(app_dir, 'templates')
    template_file = os.path.join(template_dir, 'login.html')

    print("--- DIAGNOSTIC INFORMATION ---", flush=True)
    print(f"Current Working Directory: {os.getcwd()}", flush=True)
    print(f"Path of running app.py: {app_file_path}", flush=True)
    print(f"Directory of running app.py: {app_dir}", flush=True)
    print(f"Expected templates directory: {template_dir}", flush=True)
    print(f"Expected login.html path: {template_file}", flush=True)
    print(f"Does template directory exist? -> {os.path.isdir(template_dir)}", flush=True)
    print(f"Does login.html file exist? -> {os.path.isfile(template_file)}", flush=True)
    print("--- END DIAGNOSTIC INFORMATION ---", flush=True)
    
    flask_app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static'
    )
    
    flask_app.config['SECRET_KEY'] = 'lolkek4eburek'

    @flask_app.context_processor
    def inject_current_year():
        return {'current_year': datetime.utcnow().year}

    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                return redirect(url_for('login_page'))
            return f(*args, **kwargs)
        return decorated_function

    @flask_app.route('/login', methods=['GET', 'POST'])
    def login_page():
        settings = get_all_settings()
        if request.method == 'POST':
            if request.form.get('username') == settings.get("panel_login") and \
               request.form.get('password') == settings.get("panel_password"):
                session['logged_in'] = True
                return redirect(url_for('dashboard_page'))
            else:
                flash('Неверный логин или пароль', 'danger')
        return render_template('login.html')

    @flask_app.route('/logout', methods=['POST'])
    @login_required
    def logout_page():
        session.pop('logged_in', None)
        flash('Вы успешно вышли.', 'success')
        return redirect(url_for('login_page'))

    def get_common_template_data():
        bot_status = _bot_controller.get_status()
        settings = get_all_settings()
        required_for_start = ['telegram_bot_token', 'telegram_bot_username', 'admin_telegram_id']
        all_settings_ok = all(settings.get(key) for key in required_for_start)
        return {"bot_status": bot_status, "all_settings_ok": all_settings_ok}

    @flask_app.route('/')
    @login_required
    def index():
        return redirect(url_for('dashboard_page'))

    @flask_app.route('/dashboard')
    @login_required
    def dashboard_page():
        stats = {
            "user_count": get_user_count(),
            "total_keys": get_total_keys_count(),
            "total_spent": get_total_spent_sum(),
            "host_count": len(get_all_hosts())
        }
        
        # Добавляем статистику балансировщика
        load_stats = LoadBalancer.get_total_capacity()
        
        page = request.args.get('page', 1, type=int)
        per_page = 8
        
        transactions, total_transactions = get_paginated_transactions(page=page, per_page=per_page)
        total_pages = ceil(total_transactions / per_page)
        
        chart_data = get_daily_stats_for_charts(days=30)
        common_data = get_common_template_data()
        
        return render_template(
            'dashboard.html',
            stats=stats,
            load_stats=load_stats,
            chart_data=chart_data,
            transactions=transactions,
            current_page=page,
            total_pages=total_pages,
            **common_data
        )

    @flask_app.route('/users')
    @login_required
    def users_page():
        users = get_all_users()
        for user in users:
            user['user_keys'] = get_user_keys(user['telegram_id'])
        
        common_data = get_common_template_data()
        return render_template('users.html', users=users, **common_data)

    @flask_app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings_page():
        if request.method == 'POST':
            if 'panel_password' in request.form and request.form.get('panel_password'):
                update_setting('panel_password', request.form.get('panel_password'))
            
            for key in ALL_SETTINGS_KEYS:
                if key == 'panel_password': continue

                if key in request.form:
                    if key == 'force_subscription':
                        value = 'true' if request.form[key] == 'on' else 'false'
                        update_setting(key, value)
                    elif key != 'sbp_enabled':
                        update_setting(key, request.form.get(key, ''))

            flash('Настройки успешно сохранены!', 'success')
            return redirect(url_for('settings_page'))

        current_settings = get_all_settings()
        hosts = get_all_hosts()
        for host in hosts:
            host['plans'] = get_plans_for_host(host['host_name'])
        
        common_data = get_common_template_data()
        return render_template('settings.html', settings=current_settings, hosts=hosts, **common_data)

    @flask_app.route('/start-bot', methods=['POST'])
    @login_required
    def start_bot_route():
        result = _bot_controller.start()
        flash(result['message'], 'success' if result['status'] == 'success' else 'danger')
        return redirect(request.referrer or url_for('dashboard_page'))

    @flask_app.route('/stop-bot', methods=['POST'])
    @login_required
    def stop_bot_route():
        result = _bot_controller.stop()
        flash(result['message'], 'success' if result['status'] == 'success' else 'danger')
        return redirect(request.referrer or url_for('dashboard_page'))
    
    def run_async_deploy(session_id, host_name, ssh_host, ssh_username, ssh_password, ssh_port, max_configs):
        """Запускает деплой в отдельном потоке"""
        def deploy_worker():
            with deploy_lock:
                session = deploy_sessions.get(session_id)
                if not session:
                    return
                    
            try:
                deploy_manager = AutoDeploy()
                
                # Обновляем статус
                session.update_status("validating", 10, "Проверка конфликтов серверов...")
                
                # Проверяем конфликты с использованием новой функции
                conflicts = check_server_conflicts(host_name, ssh_host, session_id)
                if conflicts:
                    session.update_status("error", 0, "", "; ".join(conflicts))
                    return
                
                session.update_status("connecting", 20, "Установка SSH соединения...")
                
                # Запускаем асинхронный деплой
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                try:
                    result = loop.run_until_complete(
                        deploy_manager.deploy_3xui(host_name, ssh_host, ssh_username, ssh_password, ssh_port, max_configs)
                    )
                finally:
                    loop.close()
                
                if result['success']:
                    session.update_status("completed", 100, "Деплой завершен успешно!", None, result)
                else:
                    session.update_status("error", 0, "", result['error'])
                    
            except Exception as e:
                logger.error(f"Deploy error for session {session_id}: {e}", exc_info=True)
                session.update_status("error", 0, "", str(e))
        
        # Запускаем в отдельном потоке
        thread = threading.Thread(target=deploy_worker, daemon=True)
        thread.start()

    @flask_app.route('/auto-deploy', methods=['GET', 'POST'])
    @login_required
    def auto_deploy_page():
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'deploy':
                # Получаем данные из формы
                host_name = request.form.get('host_name', '').strip()
                ssh_host = request.form.get('ssh_host', '').strip()
                ssh_username = request.form.get('ssh_username', '').strip()
                ssh_password = request.form.get('ssh_password', '').strip()
                ssh_port = int(request.form.get('ssh_port', 22))
                max_configs = int(request.form.get('max_configs', 20))
                
                # Валидация данных
                deploy_manager = AutoDeploy()
                validation = deploy_manager.validate_ssh_params(ssh_host, ssh_username, ssh_password, ssh_port)
                
                if not validation['valid']:
                    for error in validation['errors']:
                        flash(error, 'danger')
                    return redirect(url_for('auto_deploy_page'))
                
                if not host_name:
                    flash('Имя хоста не может быть пустым', 'danger')
                    return redirect(url_for('auto_deploy_page'))
                
                # Проверяем конфликты серверов
                conflicts = check_server_conflicts(host_name, ssh_host)
                if conflicts:
                    for conflict in conflicts:
                        flash(conflict, 'danger')
                    return redirect(url_for('auto_deploy_page'))
                
                # Создаем сессию деплоя
                session_id = str(uuid.uuid4())
                deploy_session = DeploySession(session_id, host_name, ssh_host)
                
                with deploy_lock:
                    deploy_sessions[session_id] = deploy_session
                
                # Запускаем асинхронный деплой
                run_async_deploy(session_id, host_name, ssh_host, ssh_username, ssh_password, ssh_port, max_configs)
                
                # Возвращаем JSON ответ с ID сессии для AJAX запросов
                if request.headers.get('Content-Type') == 'application/json' or request.is_json:
                    return jsonify({'success': True, 'session_id': session_id})
                
                flash('Процесс автоматического деплоя запущен в фоновом режиме. Обновите страницу через несколько минут.', 'info')
                return redirect(url_for('auto_deploy_page'))
            
            elif action == 'update_limits':
                # Обновление лимитов
                global_limit = request.form.get('global_limit')
                individual_limits = {}
                
                for key, value in request.form.items():
                    if key.startswith('limit_'):
                        host_name = key[6:]  # Убираем префикс 'limit_'
                        try:
                            individual_limits[host_name] = int(value)
                        except ValueError:
                            flash(f'Некорректный лимит для хоста {host_name}', 'danger')
                            return redirect(url_for('auto_deploy_page'))
                
                # Применяем глобальный лимит если указан
                if global_limit:
                    try:
                        global_limit = int(global_limit)
                        LoadBalancer.update_limits(None, global_limit)
                        flash(f'Глобальный лимит обновлен до {global_limit}', 'success')
                    except ValueError:
                        flash('Некорректный глобальный лимит', 'danger')
                
                # Применяем индивидуальные лимиты
                for host_name, limit in individual_limits.items():
                    LoadBalancer.update_limits(host_name, limit)
                    flash(f'Лимит для {host_name} обновлен до {limit}', 'success')
                
                return redirect(url_for('auto_deploy_page'))
            
            elif action == 'sync_counters':
                # Синхронизация счетчиков
                if LoadBalancer.synchronize_counters():
                    flash('Счетчики серверов синхронизированы', 'success')
                else:
                    flash('Ошибка синхронизации счетчиков', 'danger')
                return redirect(url_for('auto_deploy_page'))
        
        # GET запрос - показываем страницу
        hosts = get_all_hosts()
        load_stats = LoadBalancer.get_load_statistics()
        total_capacity = LoadBalancer.get_total_capacity()
        
        # Получаем данные автодеплоя
        from shop_bot.data_manager.database import get_auto_deploy_hosts
        auto_deploy_data = get_auto_deploy_hosts()
        
        common_data = get_common_template_data()
        return render_template('auto_deploy.html', 
                             hosts=hosts, 
                             load_stats=load_stats,
                             total_capacity=total_capacity,
                             auto_deploy_data=auto_deploy_data,
                             **common_data)

    @flask_app.route('/api/deploy-status/<session_id>')
    @login_required
    def get_deploy_status(session_id):
        """API endpoint для получения статуса деплоя"""
        with deploy_lock:
            session = deploy_sessions.get(session_id)
            if not session:
                return jsonify({'error': 'Session not found'}), 404
            
            return jsonify(session.to_dict())
    
    @flask_app.route('/api/deploy-sessions')
    @login_required
    def get_all_deploy_sessions():
        """API endpoint для получения всех активных сессий деплоя"""
        with deploy_lock:
            sessions = {sid: session.to_dict() for sid, session in deploy_sessions.items()}
            return jsonify(sessions)
    
    @flask_app.route('/api/deploy-cleanup', methods=['POST'])
    @login_required 
    def cleanup_deploy_sessions():
        """Очистка завершенных сессий деплоя"""
        with deploy_lock:
            # Удаляем сессии старше 1 часа
            cutoff_time = datetime.now() - timedelta(hours=1)
            to_remove = []
            
            for session_id, session in deploy_sessions.items():
                if session.created_at < cutoff_time and session.status in ['completed', 'error']:
                    to_remove.append(session_id)
            
            for session_id in to_remove:
                del deploy_sessions[session_id]
                
            return jsonify({'removed': len(to_remove), 'remaining': len(deploy_sessions)})

    @flask_app.route('/users/ban/<int:user_id>', methods=['POST'])
    @login_required
    def ban_user_route(user_id):
        ban_user(user_id)
        flash(f'Пользователь {user_id} был заблокирован.', 'success')
        return redirect(url_for('users_page'))

    @flask_app.route('/users/unban/<int:user_id>', methods=['POST'])
    @login_required
    def unban_user_route(user_id):
        unban_user(user_id)
        flash(f'Пользователь {user_id} был разблокирован.', 'success')
        return redirect(url_for('users_page'))

    @flask_app.route('/users/revoke/<int:user_id>', methods=['POST'])
    @login_required
    def revoke_keys_route(user_id):
        keys_to_revoke = get_user_keys(user_id)
        success_count = 0
        
        for key in keys_to_revoke:
            result = asyncio.run(xui_api.delete_client_on_host(key['host_name'], key['key_email']))
            if result:
                success_count += 1
        
        delete_user_keys(user_id)
        
        if success_count == len(keys_to_revoke):
            flash(f"Все {len(keys_to_revoke)} ключей для пользователя {user_id} были успешно отозваны.", 'success')
        else:
            flash(f"Удалось отозвать {success_count} из {len(keys_to_revoke)} ключей для пользователя {user_id}. Проверьте логи.", 'warning')

        return redirect(url_for('users_page'))

    @flask_app.route('/add-host', methods=['POST'])
    @login_required
    def add_host_route():
        create_host(
            name=request.form['host_name'],
            url=request.form['host_url'],
            user=request.form['host_username'],
            passwd=request.form['host_pass'],
            inbound=int(request.form['host_inbound_id'])
        )
        flash(f"Хост '{request.form['host_name']}' успешно добавлен.", 'success')
        return redirect(url_for('settings_page'))

    @flask_app.route('/delete-host/<host_name>', methods=['POST'])
    @login_required
    def delete_host_route(host_name):
        delete_host(host_name)
        flash(f"Хост '{host_name}' и все его тарифы были удалены.", 'success')
        return redirect(url_for('settings_page'))

    @flask_app.route('/add-plan', methods=['POST'])
    @login_required
    def add_plan_route():
        create_plan(
            host_name=request.form['host_name'],
            plan_name=request.form['plan_name'],
            months=int(request.form['months']),
            price=float(request.form['price'])
        )
        flash(f"Новый тариф для хоста '{request.form['host_name']}' добавлен.", 'success')
        return redirect(url_for('settings_page'))

    @flask_app.route('/delete-plan/<int:plan_id>', methods=['POST'])
    @login_required
    def delete_plan_route(plan_id):
        delete_plan(plan_id)
        flash("Тариф успешно удален.", 'success')
        return redirect(url_for('settings_page'))

    @flask_app.route('/yookassa-webhook', methods=['POST'])
    def yookassa_webhook_handler():
        try:
            event_json = request.json
            if event_json.get("event") == "payment.succeeded":
                metadata = event_json.get("object", {}).get("metadata", {})
                
                bot = _bot_controller.get_bot_instance()
                payment_processor = handlers.process_successful_payment

                if metadata and bot is not None and payment_processor is not None:
                    loop = current_app.config.get('EVENT_LOOP')
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
                    else:
                        logger.error("YooKassa webhook: Event loop is not available!")
            return 'OK', 200
        except Exception as e:
            logger.error(f"Error in yookassa webhook handler: {e}", exc_info=True)
            return 'Error', 500
        
    @flask_app.route('/cryptobot-webhook', methods=['POST'])
    def cryptobot_webhook_handler():
        try:
            request_data = request.json
            
            if request_data and request_data.get('update_type') == 'invoice_paid':
                payload_data = request_data.get('payload', {})
                
                payload_string = payload_data.get('payload')
                
                if not payload_string:
                    logger.warning("CryptoBot Webhook: Received paid invoice but payload was empty.")
                    return 'OK', 200

                parts = payload_string.split(':')
                if len(parts) < 9:
                    logger.error(f"cryptobot Webhook: Invalid payload format received: {payload_string}")
                    return 'Error', 400

                metadata = {
                    "user_id": parts[0],
                    "months": parts[1],
                    "price": parts[2],
                    "action": parts[3],
                    "key_id": parts[4],
                    "host_name": parts[5],
                    "plan_id": parts[6],
                    "customer_email": parts[7] if parts[7] != 'None' else None,
                    "payment_method": parts[8]
                }
                
                bot = _bot_controller.get_bot_instance()
                loop = current_app.config.get('EVENT_LOOP')
                payment_processor = handlers.process_successful_payment

                if bot and loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
                else:
                    logger.error("cryptobot Webhook: Could not process payment because bot or event loop is not running.")

            return 'OK', 200
            
        except Exception as e:
            logger.error(f"Error in cryptobot webhook handler: {e}", exc_info=True)
            return 'Error', 500
        
    @flask_app.route('/heleket-webhook', methods=['POST'])
    def heleket_webhook_handler():
        try:
            data = request.json
            logger.info(f"Received Heleket webhook: {data}")

            api_key = get_setting("heleket_api_key")
            if not api_key: return 'Error', 500

            sign = data.pop("sign", None)
            if not sign: return 'Error', 400
                
            sorted_data_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
            
            base64_encoded = base64.b64encode(sorted_data_str.encode()).decode()
            raw_string = f"{base64_encoded}{api_key}"
            expected_sign = hashlib.md5(raw_string.encode()).hexdigest()

            if not compare_digest(expected_sign, sign):
                logger.warning("Heleket webhook: Invalid signature.")
                return 'Forbidden', 403

            if data.get('status') in ["paid", "paid_over"]:
                metadata_str = data.get('description')
                if not metadata_str: return 'Error', 400
                
                metadata = json.loads(metadata_str)
                
                bot = _bot_controller.get_bot_instance()
                loop = current_app.config.get('EVENT_LOOP')
                payment_processor = handlers.process_successful_payment

                if bot and loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
            
            return 'OK', 200
        except Exception as e:
            logger.error(f"Error in heleket webhook handler: {e}", exc_info=True)
            return 'Error', 500
        
    @flask_app.route('/ton-webhook', methods=['POST'])
    def ton_webhook_handler():
        try:
            data = request.json
            logger.info(f"Received TonAPI webhook: {data}")

            if 'tx_id' in data:
                account_id = data.get('account_id')
                for tx in data.get('in_progress_txs', []) + data.get('txs', []):
                    in_msg = tx.get('in_msg')
                    if in_msg and in_msg.get('decoded_comment'):
                        payment_id = in_msg['decoded_comment']
                        amount_nano = int(in_msg.get('value', 0))
                        amount_ton = float(amount_nano / 1_000_000_000)

                        metadata = find_and_complete_ton_transaction(payment_id, amount_ton)
                        
                        if metadata:
                            logger.info(f"TON Payment successful for payment_id: {payment_id}")
                            bot = _bot_controller.get_bot_instance()
                            loop = current_app.config.get('EVENT_LOOP')
                            payment_processor = handlers.process_successful_payment

                            if bot and loop and loop.is_running():
                                asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
            
            return 'OK', 200
        except Exception as e:
            logger.error(f"Error in ton webhook handler: {e}", exc_info=True)
            return 'Error', 500

    return flask_app