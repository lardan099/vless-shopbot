import sqlite3
from datetime import datetime
import logging
from pathlib import Path
import json
import time

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path("/app/project")
DB_FILE = PROJECT_ROOT / "users.db"

def initialize_db():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    telegram_id INTEGER PRIMARY KEY, username TEXT, total_spent REAL DEFAULT 0,
                    total_months INTEGER DEFAULT 0, trial_used BOOLEAN DEFAULT 0,
                    agreed_to_terms BOOLEAN DEFAULT 0,
                    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_banned BOOLEAN DEFAULT 0,
                    referred_by INTEGER,
                    referral_balance REAL DEFAULT 0
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vpn_keys (
                    key_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    host_name TEXT NOT NULL,
                    xui_client_uuid TEXT NOT NULL,
                    key_email TEXT NOT NULL UNIQUE,
                    expiry_date TIMESTAMP,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    username TEXT,
                    transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payment_id TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    amount_rub REAL NOT NULL,
                    amount_currency REAL,
                    currency_name TEXT,
                    payment_method TEXT,
                    metadata TEXT,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bot_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS xui_hosts(
                    host_name TEXT NOT NULL,
                    host_url TEXT NOT NULL,
                    host_username TEXT NOT NULL,
                    host_pass TEXT NOT NULL,
                    host_inbound_id INTEGER NOT NULL,
                    max_configs INTEGER DEFAULT 20,
                    current_configs INTEGER DEFAULT 0
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS plans (
                    plan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_name TEXT NOT NULL,
                    plan_name TEXT NOT NULL,
                    months INTEGER NOT NULL,
                    price REAL NOT NULL,
                    FOREIGN KEY (host_name) REFERENCES xui_hosts (host_name)
                )
            ''')            
            default_settings = {
                "panel_login": "admin",
                "panel_password": "admin",
                "about_text": None,
                "terms_url": None,
                "privacy_url": None,
                "support_user": None,
                "support_text": None,
                "channel_url": None,
                "force_subscription": "true",
                "receipt_email": "example@example.com",
                "telegram_bot_token": None,
                "telegram_bot_username": None,
                "referral_percentage": "10",
                "referral_discount": "5",
                "admin_telegram_id": None,
                "yookassa_shop_id": None,
                "yookassa_secret_key": None,
                "sbp_enabled": "false",
                "cryptobot_token": None,
                "heleket_merchant_id": None,
                "heleket_api_key": None,
                "domain": None,
                "ton_wallet_address": None,
                "tonapi_key": None,
            }
            run_migration()
            for key, value in default_settings.items():
                cursor.execute("INSERT OR IGNORE INTO bot_settings (key, value) VALUES (?, ?)", (key, value))
            conn.commit()
            logging.info("Database initialized successfully.")
            
            # Выводим диагностическую информацию
            debug_database_status()
    except sqlite3.Error as e:
        logging.error(f"Database error on initialization: {e}")

def run_migration():
    if not DB_FILE.exists():
        logging.error("Users.db database file was not found. There is nothing to migrate.")
        return

    logging.info(f"Starting the migration of the database: {DB_FILE}")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        logging.info("The migration of the table 'users' ...")
    
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'referred_by' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN referred_by INTEGER")
            logging.info(" -> The column 'referred_by' is successfully added.")
        else:
            logging.info(" -> The column 'referred_by' already exists.")
            
        if 'referral_balance' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN referral_balance REAL DEFAULT 0")
            logging.info(" -> The column 'referral_balance' is successfully added.")
        else:
            logging.info(" -> The column 'referral_balance' already exists.")
        
        logging.info("The table 'users' has been successfully updated.")

        logging.info("The migration of the table 'Transactions' ...")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'")
        table_exists = cursor.fetchone()

        if table_exists:
            cursor.execute("PRAGMA table_info(transactions)")
            trans_columns = [row[1] for row in cursor.fetchall()]
            
            if 'payment_id' in trans_columns and 'status' in trans_columns and 'username' in trans_columns:
                logging.info("The 'Transactions' table already has a new structure. Migration is not required.")
            else:
                backup_name = f"transactions_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                logging.warning(f"The old structure of the TRANSACTIONS table was discovered. I rename in '{backup_name}' ...")
                cursor.execute(f"ALTER TABLE transactions RENAME TO {backup_name}")
                
                logging.info("I create a new table 'Transactions' with the correct structure ...")
                create_new_transactions_table(cursor)
                logging.info("The new table 'Transactions' has been successfully created. The old data is saved.")
        else:
            logging.info("TRANSACTIONS table was not found. I create a new one ...")
            create_new_transactions_table(cursor)
            logging.info("The new table 'Transactions' has been successfully created.")

        # Миграция таблицы xui_hosts для добавления max_configs
        logging.info("The migration of the table 'xui_hosts' ...")
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='xui_hosts'")
        hosts_table_exists = cursor.fetchone()
        
        if hosts_table_exists:
            cursor.execute("PRAGMA table_info(xui_hosts)")
            hosts_columns = [row[1] for row in cursor.fetchall()]
            
            if 'max_configs' not in hosts_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN max_configs INTEGER DEFAULT 20")
                logging.info(" -> The column 'max_configs' is successfully added to xui_hosts.")
            else:
                logging.info(" -> The column 'max_configs' already exists in xui_hosts.")
                
            if 'current_configs' not in hosts_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN current_configs INTEGER DEFAULT 0")
                logging.info(" -> The column 'current_configs' is successfully added to xui_hosts.")
            else:
                logging.info(" -> The column 'current_configs' already exists in xui_hosts.")

        conn.commit()
        conn.close()
        
        logging.info("--- The database is successfully completed! ---")

    except sqlite3.Error as e:
        logging.error(f"An error occurred during migration: {e}")

def create_new_transactions_table(cursor: sqlite3.Cursor):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            username TEXT,
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            amount_rub REAL NOT NULL,
            amount_currency REAL,
            currency_name TEXT,
            payment_method TEXT,
            metadata TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

def create_host(name: str, url: str, user: str, passwd: str, inbound: int, max_configs: int = 20):
    try:
        with sqlite3.connect(DB_FILE, timeout=60.0) as conn:
            cursor = conn.cursor()
            
            # Валидация входящих данных
            if not all([name, url, user, passwd]) or inbound is None:
                logger.error(f"Invalid host data: name='{name}', url='{url}', user='{user}', inbound={inbound}")
                return
            
            if inbound < 1:
                logger.warning(f"Inbound ID {inbound} is unusual. For new 3x-ui installations, inbound ID should typically be 1 or higher")
            
            # Проверяем, существует ли уже хост с таким именем
            cursor.execute("SELECT host_name FROM xui_hosts WHERE host_name = ?", (name,))
            existing_host = cursor.fetchone()
            
            if existing_host:
                logger.warning(f"Host '{name}' already exists, updating instead")
                cursor.execute(
                    "UPDATE xui_hosts SET host_url = ?, host_username = ?, host_pass = ?, host_inbound_id = ?, max_configs = ? WHERE host_name = ?",
                    (url, user, passwd, inbound, max_configs, name)
                )
            else:
                logger.info(f"Creating new host: {name} -> {url} (inbound_id: {inbound}, max_configs: {max_configs})")
                cursor.execute(
                    "INSERT INTO xui_hosts (host_name, host_url, host_username, host_pass, host_inbound_id, max_configs, current_configs) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name, url, user, passwd, inbound, max_configs, 0)
                )
            
            conn.commit()
            logger.info(f"Successfully created/updated host: {name}")
            
            # Проверяем, что хост действительно добавлен
            cursor.execute("SELECT * FROM xui_hosts WHERE host_name = ?", (name,))
            result = cursor.fetchone()
            if result:
                logger.info(f"Host verification successful: {name} is in database")
            else:
                logger.error(f"Host verification failed: {name} not found in database")
                
    except sqlite3.Error as e:
        logger.error(f"Error creating host '{name}': {e}")
        # Не пробрасываем ошибку, просто логируем

def delete_host(host_name: str):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM plans WHERE host_name = ?", (host_name,))
            cursor.execute("DELETE FROM xui_hosts WHERE host_name = ?", (host_name,))
            conn.commit()
            logging.info(f"Successfully deleted host '{host_name}' and its plans.")
    except sqlite3.Error as e:
        logging.error(f"Error deleting host '{host_name}': {e}")

def get_host(host_name: str) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM xui_hosts WHERE host_name = ?", (host_name,))
            result = cursor.fetchone()
            return dict(result) if result else None
    except sqlite3.Error as e:
        logging.error(f"Error getting host '{host_name}': {e}")
        return None

def get_all_hosts() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM xui_hosts")
            hosts = cursor.fetchall()
            return [dict(row) for row in hosts]
    except sqlite3.Error as e:
        logging.error(f"Error getting list of all hosts: {e}")
        return []

def get_all_keys() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vpn_keys")
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Failed to get all keys: {e}")
        return []

def get_setting(key: str) -> str | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM bot_settings WHERE key = ?", (key,))
            result = cursor.fetchone()
            return result[0] if result else None
    except sqlite3.Error as e:
        logging.error(f"Failed to get setting '{key}': {e}")
        return None
        
def get_all_settings() -> dict:
    settings = {}
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM bot_settings")
            rows = cursor.fetchall()
            for row in rows:
                settings[row['key']] = row['value']
    except sqlite3.Error as e:
        logging.error(f"Failed to get all settings: {e}")
    return settings

def update_setting(key: str, value: str):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE bot_settings SET value = ? WHERE key = ?", (value, key))
            conn.commit()
            logging.info(f"Setting '{key}' updated.")
    except sqlite3.Error as e:
        logging.error(f"Failed to update setting '{key}': {e}")

def create_plan(host_name: str, plan_name: str, months: int, price: float):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO plans (host_name, plan_name, months, price) VALUES (?, ?, ?, ?)",
                (host_name, plan_name, months, price)
            )
            conn.commit()
            logging.info(f"Created new plan '{plan_name}' for host '{host_name}'.")
    except sqlite3.Error as e:
        logging.error(f"Failed to create plan for host '{host_name}': {e}")

def get_plans_for_host(host_name: str) -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM plans WHERE host_name = ? ORDER BY months", (host_name,))
            plans = cursor.fetchall()
            return [dict(plan) for plan in plans]
    except sqlite3.Error as e:
        logging.error(f"Failed to get plans for host '{host_name}': {e}")
        return []

def get_plan_by_id(plan_id: int) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM plans WHERE plan_id = ?", (plan_id,))
            plan = cursor.fetchone()
            return dict(plan) if plan else None
    except sqlite3.Error as e:
        logging.error(f"Failed to get plan by id '{plan_id}': {e}")
        return None

def delete_plan(plan_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM plans WHERE plan_id = ?", (plan_id,))
            conn.commit()
            logging.info(f"Deleted plan with id {plan_id}.")
    except sqlite3.Error as e:
        logging.error(f"Failed to delete plan with id {plan_id}: {e}")

def register_user_if_not_exists(telegram_id: int, username: str, referrer_id):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT telegram_id FROM users WHERE telegram_id = ?", (telegram_id,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO users (telegram_id, username, registration_date, referred_by) VALUES (?, ?, ?, ?)",
                    (telegram_id, username, datetime.now(), referrer_id)
                )
            else:
                cursor.execute("UPDATE users SET username = ? WHERE telegram_id = ?", (username, telegram_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to register user {telegram_id}: {e}")

def add_to_referral_balance(user_id: int, amount: float):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET referral_balance = referral_balance + ? WHERE telegram_id = ?", (amount, user_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to add to referral balance for user {user_id}: {e}")

def get_referral_count(user_id: int) -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE referred_by = ?", (user_id,))
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error(f"Failed to get referral count for user {user_id}: {e}")
        return 0

def get_user(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,))
            user_data = cursor.fetchone()
            return dict(user_data) if user_data else None
    except sqlite3.Error as e:
        logging.error(f"Failed to get user {telegram_id}: {e}")
        return None

def set_terms_agreed(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET agreed_to_terms = 1 WHERE telegram_id = ?", (telegram_id,))
            conn.commit()
            logging.info(f"User {telegram_id} has agreed to terms.")
    except sqlite3.Error as e:
        logging.error(f"Failed to set terms agreed for user {telegram_id}: {e}")

def update_user_stats(telegram_id: int, amount_spent: float, months_purchased: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET total_spent = total_spent + ?, total_months = total_months + ? WHERE telegram_id = ?", (amount_spent, months_purchased, telegram_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to update user stats for {telegram_id}: {e}")

def get_user_count() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error(f"Failed to get user count: {e}")
        return 0

def get_total_keys_count() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM vpn_keys")
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error(f"Failed to get total keys count: {e}")
        return 0

def get_total_spent_sum() -> float:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT SUM(total_spent) FROM users")
            return cursor.fetchone()[0] or 0.0
    except sqlite3.Error as e:
        logging.error(f"Failed to get total spent sum: {e}")
        return 0.0

def create_pending_transaction(payment_id: str, user_id: int, amount_rub: float, metadata: dict) -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO transactions (payment_id, user_id, status, amount_rub, metadata) VALUES (?, ?, ?, ?, ?)",
                (payment_id, user_id, 'pending', amount_rub, json.dumps(metadata))
            )
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        logging.error(f"Failed to create pending transaction: {e}")
        return 0

def find_and_complete_ton_transaction(payment_id: str, amount_ton: float) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM transactions WHERE payment_id = ? AND status = 'pending'", (payment_id,))
            transaction = cursor.fetchone()
            if not transaction:
                logger.warning(f"TON Webhook: Received payment for unknown or completed payment_id: {payment_id}")
                return None
            
            
            cursor.execute(
                "UPDATE transactions SET status = 'paid', amount_currency = ?, currency_name = 'TON', payment_method = 'TON' WHERE payment_id = ?",
                (amount_ton, payment_id)
            )
            conn.commit()
            
            return json.loads(transaction['metadata'])
    except sqlite3.Error as e:
        logging.error(f"Failed to complete TON transaction {payment_id}: {e}")
        return None

def log_transaction(username: str, transaction_id: str | None, payment_id: str | None, user_id: int, status: str, amount_rub: float, amount_currency: float | None, currency_name: str | None, payment_method: str, metadata: str):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO transactions
                   (username, transaction_id, payment_id, user_id, status, amount_rub, amount_currency, currency_name, payment_method, metadata, created_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (username, transaction_id, payment_id, user_id, status, amount_rub, amount_currency, currency_name, payment_method, metadata, datetime.now())
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to log transaction for user {user_id}: {e}")

def get_paginated_transactions(page: int = 1, per_page: int = 15) -> tuple[list[dict], int]:
    offset = (page - 1) * per_page
    transactions = []
    total = 0
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM transactions")
            total = cursor.fetchone()[0]

            query = "SELECT * FROM transactions ORDER BY created_date DESC LIMIT ? OFFSET ?"
            cursor.execute(query, (per_page, offset))
            
            for row in cursor.fetchall():
                transaction_dict = dict(row)
                
                metadata_str = transaction_dict.get('metadata')
                if metadata_str:
                    try:
                        metadata = json.loads(metadata_str)
                        transaction_dict['host_name'] = metadata.get('host_name', 'N/A')
                        transaction_dict['plan_name'] = metadata.get('plan_name', 'N/A')
                    except json.JSONDecodeError:
                        transaction_dict['host_name'] = 'Error'
                        transaction_dict['plan_name'] = 'Error'
                else:
                    transaction_dict['host_name'] = 'N/A'
                    transaction_dict['plan_name'] = 'N/A'
                
                transactions.append(transaction_dict)
            
    except sqlite3.Error as e:
        logging.error(f"Failed to get paginated transactions: {e}")
    
    return transactions, total

def set_trial_used(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET trial_used = 1 WHERE telegram_id = ?", (telegram_id,))
            conn.commit()
            logging.info(f"Trial period marked as used for user {telegram_id}.")
    except sqlite3.Error as e:
        logging.error(f"Failed to set trial used for user {telegram_id}: {e}")

def add_new_key(user_id: int, host_name: str, xui_client_uuid: str, key_email: str, expiry_timestamp_ms: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            expiry_date = datetime.fromtimestamp(expiry_timestamp_ms / 1000)
            cursor.execute(
                "INSERT INTO vpn_keys (user_id, host_name, xui_client_uuid, key_email, expiry_date) VALUES (?, ?, ?, ?, ?)",
                (user_id, host_name, xui_client_uuid, key_email, expiry_date)
            )
            new_key_id = cursor.lastrowid
            conn.commit()
            return new_key_id
    except sqlite3.Error as e:
        logging.error(f"Failed to add new key for user {user_id}: {e}")
        return None

def get_user_keys(user_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vpn_keys WHERE user_id = ? ORDER BY key_id", (user_id,))
            keys = cursor.fetchall()
            return [dict(key) for key in keys]
    except sqlite3.Error as e:
        logging.error(f"Failed to get keys for user {user_id}: {e}")
        return []

def get_key_by_id(key_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vpn_keys WHERE key_id = ?", (key_id,))
            key_data = cursor.fetchone()
            return dict(key_data) if key_data else None
    except sqlite3.Error as e:
        logging.error(f"Failed to get key by ID {key_id}: {e}")
        return None

def update_key_info(key_id: int, new_xui_uuid: str, new_expiry_ms: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            expiry_date = datetime.fromtimestamp(new_expiry_ms / 1000)
            cursor.execute("UPDATE vpn_keys SET xui_client_uuid = ?, expiry_date = ? WHERE key_id = ?", (new_xui_uuid, expiry_date, key_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to update key {key_id}: {e}")

def get_next_key_number(user_id: int) -> int:
    keys = get_user_keys(user_id)
    return len(keys) + 1

def get_keys_for_host(host_name: str) -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vpn_keys WHERE host_name = ?", (host_name,))
            keys = cursor.fetchall()
            return [dict(key) for key in keys]
    except sqlite3.Error as e:
        logging.error(f"Failed to get keys for host '{host_name}': {e}")
        return []

def get_best_available_host() -> dict | None:
    """Получает хост с наименьшей загрузкой для создания нового ключа"""
    try:
        hosts = get_all_hosts()
        if not hosts:
            return None
        
        best_host = None
        min_load_percentage = 100
        
        for host in hosts:
            # Получаем текущее количество ключей для хоста
            current_keys = len(get_keys_for_host(host['host_name']))
            max_configs = getattr(host, 'max_configs', 20)  # Значение по умолчанию
            
            load_percentage = (current_keys / max_configs) * 100 if max_configs > 0 else 100
            
            if load_percentage < min_load_percentage and load_percentage < 100:
                min_load_percentage = load_percentage
                # Добавляем поля для совместимости с load_balancer
                best_host = host.copy()
                best_host['current_configs'] = current_keys
                best_host['max_configs'] = max_configs
                best_host['load_percentage'] = round(load_percentage, 2)
        
        return best_host
    except Exception as e:
        logging.error(f"Error getting best available host: {e}")
        return None

def increment_host_config_count(host_name: str):
    """Увеличивает счетчик конфигураций для хоста (заглушка для совместимости)"""
    # В текущей реализации счетчик ключей ведется через таблицу vpn_keys
    # Эта функция оставлена для совместимости с load_balancer
    pass

def decrement_host_config_count(host_name: str):
    """Уменьшает счетчик конфигураций для хоста (заглушка для совместимости)"""
    # В текущей реализации счетчик ключей ведется через таблицу vpn_keys
    # Эта функция оставлена для совместимости с load_balancer
    pass

def sync_host_config_counts():
    """Синхронизирует счетчики конфигураций (заглушка для совместимости)"""
    # В текущей реализации счетчик ключей ведется через таблицу vpn_keys
    # Эта функция оставлена для совместимости с load_balancer
    pass

def get_hosts_load_status() -> list[dict]:
    """Возвращает статистику загрузки всех хостов"""
    try:
        hosts = get_all_hosts()
        if not hosts:
            logger.info("No hosts found in database")
            return []
        
        load_stats = []
        
        for host in hosts:
            # Получаем текущее количество ключей для хоста
            current_keys = len(get_keys_for_host(host['host_name']))
            
            # Проверяем есть ли колонка max_configs в таблице xui_hosts
            # Если нет, используем значение по умолчанию
            max_configs = host.get('max_configs', 20)  # Значение по умолчанию
            
            load_percentage = (current_keys / max_configs) * 100 if max_configs > 0 else 100
            
            load_stats.append({
                'host_name': host['host_name'],
                'current_configs': current_keys,
                'max_configs': max_configs,
                'load_percentage': round(load_percentage, 2)
            })
            
            logger.debug(f"Host {host['host_name']}: {current_keys}/{max_configs} configs ({load_percentage:.1f}%)")
        
        logger.info(f"Found {len(load_stats)} hosts for load statistics")
        return load_stats
    except Exception as e:
        logger.error(f"Error getting hosts load status: {e}")
        return []

def update_host_limits(host_name: str = None, max_configs: int = None):
    """Обновляет лимиты конфигураций для хостов (заглушка для совместимости)"""
    # В текущей реализации лимиты не хранятся в базе данных
    # Эта функция оставлена для совместимости с load_balancer
    # В будущем можно добавить колонку max_configs в таблицу xui_hosts
    if host_name and max_configs:
        logging.info(f"Would update limits for host '{host_name}' to {max_configs} (not implemented)")
    elif max_configs:
        logging.info(f"Would update limits for all hosts to {max_configs} (not implemented)")
    else:
        logging.info("Update host limits called without parameters")
    pass

def create_auto_deploy_host(name: str, ssh_host: str, ssh_username: str, ssh_password: str, ssh_port: int, max_configs: int, panel_port: int, panel_username: str, panel_password: str, panel_secpath: str) -> str:
    """Создает запись хоста для автоматического деплоя и возвращает его ID"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Сначала проверим, есть ли таблица для хранения данных деплоя
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auto_deploy_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    ssh_host TEXT NOT NULL,
                    ssh_username TEXT NOT NULL,
                    ssh_password TEXT NOT NULL,
                    ssh_port INTEGER NOT NULL,
                    max_configs INTEGER NOT NULL,
                    panel_port INTEGER NOT NULL,
                    panel_username TEXT NOT NULL,
                    panel_password TEXT NOT NULL,
                    panel_secpath TEXT NOT NULL,
                    panel_url TEXT,
                    inbound_id INTEGER,
                    status TEXT DEFAULT 'deploying',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                INSERT INTO auto_deploy_hosts 
                (name, ssh_host, ssh_username, ssh_password, ssh_port, max_configs, panel_port, panel_username, panel_password, panel_secpath)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, ssh_host, ssh_username, ssh_password, ssh_port, max_configs, panel_port, panel_username, panel_password, panel_secpath))
            
            host_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"Created auto-deploy host record: {host_id} for {name}")
            return str(host_id)
        
    except Exception as e:
        logger.error(f"Error creating auto-deploy host: {e}")
        return None

def update_host_after_deploy(host_id: str, host_url: str, host_username: str, host_password: str, inbound_id: int, ssh_public_key: str = "", new_ssh_port: int = None, new_ssh_password: str = ""):
    """Обновляет запись хоста после успешного деплоя"""
    try:
        with sqlite3.connect(DB_FILE, timeout=60.0) as conn:
            cursor = conn.cursor()
            
            # Добавляем колонки если их нет
            try:
                cursor.execute("ALTER TABLE auto_deploy_hosts ADD COLUMN ssh_public_key TEXT")
            except:
                pass  # Колонка уже существует
            
            try:
                cursor.execute("ALTER TABLE auto_deploy_hosts ADD COLUMN new_ssh_port INTEGER")
            except:
                pass  # Колонка уже существует
            
            try:
                cursor.execute("ALTER TABLE auto_deploy_hosts ADD COLUMN new_ssh_password TEXT")
            except:
                pass  # Колонка уже существует
            
            # Обновляем запись в таблице автодеплоя
            cursor.execute("""
                UPDATE auto_deploy_hosts 
                SET panel_url = ?, inbound_id = ?, ssh_public_key = ?, new_ssh_port = ?, new_ssh_password = ?, status = 'completed'
                WHERE id = ?
            """, (host_url, inbound_id, ssh_public_key, new_ssh_port, new_ssh_password, host_id))
            
            # Получаем данные для добавления в основную таблицу
            cursor.execute("""
                SELECT name, max_configs FROM auto_deploy_hosts WHERE id = ?
            """, (host_id,))
            
            result = cursor.fetchone()
            if result:
                host_name, max_configs = result
                
                # Валидация входящих данных
                if not all([host_name, host_url, host_username, host_password]) or inbound_id is None:
                    logger.error(f"Invalid host data: name='{host_name}', url='{host_url}', user='{host_username}', inbound={inbound_id}")
                    return False
                
                if inbound_id < 1:
                    logger.warning(f"Inbound ID {inbound_id} is unusual. For new 3x-ui installations, inbound ID should typically be 1 or higher")
                
                # Проверяем, существует ли уже хост с таким именем
                cursor.execute("SELECT host_name FROM xui_hosts WHERE host_name = ?", (host_name,))
                existing_host = cursor.fetchone()
                
                if existing_host:
                    logger.warning(f"Host '{host_name}' already exists, updating instead")
                    cursor.execute(
                        "UPDATE xui_hosts SET host_url = ?, host_username = ?, host_pass = ?, host_inbound_id = ?, max_configs = ? WHERE host_name = ?",
                        (host_url, host_username, host_password, inbound_id, max_configs, host_name)
                    )
                else:
                    logger.info(f"Creating new host in main table: {host_name} -> {host_url} (inbound_id: {inbound_id}, max_configs: {max_configs})")
                    cursor.execute(
                        "INSERT INTO xui_hosts (host_name, host_url, host_username, host_pass, host_inbound_id, max_configs, current_configs) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (host_name, host_url, host_username, host_password, inbound_id, max_configs, 0)
                    )
                
                # Проверяем, что хост действительно добавлен
                cursor.execute("SELECT * FROM xui_hosts WHERE host_name = ?", (host_name,))
                verification = cursor.fetchone()
                if verification:
                    logger.info(f"Host verification successful: {host_name} is in database")
                else:
                    logger.error(f"Host verification failed: {host_name} not found in database")
                    return False
                    
                logger.info(f"Host {host_name} created successfully in main table")
            else:
                logger.error(f"No auto_deploy_hosts record found for ID: {host_id}")
                return False
            
            conn.commit()
            
            logger.info(f"Updated host after deploy: {host_id}")
            return True
            
    except Exception as e:
        logger.error(f"Error updating host after deploy: {e}")
        return False

def get_auto_deploy_hosts():
    """Получает все записи автодеплоя"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Создаем таблицу, если её нет
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auto_deploy_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    ssh_host TEXT NOT NULL,
                    ssh_username TEXT NOT NULL,
                    ssh_password TEXT NOT NULL,
                    ssh_port INTEGER NOT NULL,
                    max_configs INTEGER NOT NULL,
                    panel_port INTEGER NOT NULL,
                    panel_username TEXT NOT NULL,
                    panel_password TEXT NOT NULL,
                    panel_secpath TEXT NOT NULL,
                    panel_url TEXT,
                    inbound_id INTEGER,
                    status TEXT DEFAULT 'deploying',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                SELECT * FROM auto_deploy_hosts 
                ORDER BY created_at DESC
            """)
            rows = cursor.fetchall()
            
            # Преобразуем в список словарей
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        
    except Exception as e:
        logger.error(f"Error getting auto-deploy hosts: {e}")
        return []

def get_all_vpn_users():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT user_id FROM vpn_keys")
            users = cursor.fetchall()
            return [dict(user) for user in users]
    except sqlite3.Error as e:
        logging.error(f"Failed to get all vpn users: {e}")
        return []

def update_key_status_from_server(key_email: str, xui_client_data):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            if xui_client_data:
                expiry_date = datetime.fromtimestamp(xui_client_data.expiry_time / 1000)
                cursor.execute("UPDATE vpn_keys SET xui_client_uuid = ?, expiry_date = ? WHERE key_email = ?", (xui_client_data.id, expiry_date, key_email))
            else:
                cursor.execute("DELETE FROM vpn_keys WHERE key_email = ?", (key_email,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to update key status for {key_email}: {e}")

def get_daily_stats_for_charts(days: int = 30) -> dict:
    stats = {'users': {}, 'keys': {}}
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            query_users = """
                SELECT date(registration_date) as day, COUNT(*)
                FROM users
                WHERE registration_date >= date('now', ?)
                GROUP BY day
                ORDER BY day;
            """
            cursor.execute(query_users, (f'-{days} days',))
            for row in cursor.fetchall():
                stats['users'][row[0]] = row[1]
            
            query_keys = """
                SELECT date(created_date) as day, COUNT(*)
                FROM vpn_keys
                WHERE created_date >= date('now', ?)
                GROUP BY day
                ORDER BY day;
            """
            cursor.execute(query_keys, (f'-{days} days',))
            for row in cursor.fetchall():
                stats['keys'][row[0]] = row[1]
    except sqlite3.Error as e:
        logging.error(f"Failed to get daily stats for charts: {e}")
    return stats


def get_recent_transactions(limit: int = 15) -> list[dict]:
    transactions = []
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            query = """
                SELECT
                    k.key_id,
                    k.host_name,
                    k.created_date,
                    u.telegram_id,
                    u.username
                FROM vpn_keys k
                JOIN users u ON k.user_id = u.telegram_id
                ORDER BY k.created_date DESC
                LIMIT ?;
            """
            cursor.execute(query, (limit,))
            transactions = [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Failed to get recent transactions: {e}")
    return transactions

def get_all_users() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users ORDER BY registration_date DESC")
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Failed to get all users: {e}")
        return []

def debug_database_status():
    """Выводит диагностическую информацию о состоянии базы данных"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Проверяем таблицы
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            logger.info(f"Database tables: {tables}")
            
            # Проверяем структуру таблицы xui_hosts
            if 'xui_hosts' in tables:
                cursor.execute("PRAGMA table_info(xui_hosts)")
                columns = cursor.fetchall()
                logger.info(f"xui_hosts columns: {[(col[1], col[2]) for col in columns]}")
                
                # Считаем записи в xui_hosts
                cursor.execute("SELECT COUNT(*) FROM xui_hosts")
                hosts_count = cursor.fetchone()[0]
                logger.info(f"Total hosts in xui_hosts: {hosts_count}")
                
                if hosts_count > 0:
                    cursor.execute("SELECT host_name, host_url, max_configs FROM xui_hosts")
                    hosts = cursor.fetchall()
                    for host in hosts:
                        logger.info(f"Host: {host[0]} -> {host[1]} (max_configs: {host[2] if len(host) > 2 else 'N/A'})")
            
            # Проверяем таблицу auto_deploy_hosts
            if 'auto_deploy_hosts' in tables:
                cursor.execute("SELECT COUNT(*) FROM auto_deploy_hosts")
                auto_deploy_count = cursor.fetchone()[0]
                logger.info(f"Total auto_deploy_hosts: {auto_deploy_count}")
                
                if auto_deploy_count > 0:
                    cursor.execute("SELECT name, status, created_at FROM auto_deploy_hosts ORDER BY created_at DESC LIMIT 5")
                    auto_hosts = cursor.fetchall()
                    for host in auto_hosts:
                        logger.info(f"Auto-deploy: {host[0]} - {host[1]} ({host[2]})")
            
            return True
    except sqlite3.Error as e:
        logger.error(f"Database debug failed: {e}")
        return False

def ban_user(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_banned = 1 WHERE telegram_id = ?", (telegram_id,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to ban user {telegram_id}: {e}")

def unban_user(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_banned = 0 WHERE telegram_id = ?", (telegram_id,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to unban user {telegram_id}: {e}")

def delete_user_keys(user_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vpn_keys WHERE user_id = ?", (user_id,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to delete keys for user {user_id}: {e}")