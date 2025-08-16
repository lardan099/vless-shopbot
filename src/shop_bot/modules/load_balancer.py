import logging
from typing import Dict, Optional
from shop_bot.data_manager.database import (
    get_best_available_host, increment_host_config_count, 
    decrement_host_config_count, get_hosts_load_status,
    update_host_limits, sync_host_config_counts
)

logger = logging.getLogger(__name__)

class LoadBalancer:
    """Балансировщик нагрузки для серверов VPN"""
    
    @staticmethod
    def get_optimal_host() -> Optional[Dict]:
        """
        Возвращает оптимальный хост для создания новой конфигурации.
        
        Returns:
            Dict: Данные хоста с наименьшей нагрузкой или None, если все хосты на лимите
        """
        try:
            host = get_best_available_host()
            if host:
                logger.info(f"Selected host '{host['host_name']}' with {host['current_configs']}/{host['max_configs']} configs")
                return host
            else:
                logger.warning("No available hosts found - all hosts are at their limit!")
                return None
        except Exception as e:
            logger.error(f"Error selecting optimal host: {e}")
            return None
    
    @staticmethod
    def allocate_config_to_host(host_name: str) -> bool:
        """
        Выделяет слот конфигурации на указанном хосте.
        
        Args:
            host_name: Имя хоста
            
        Returns:
            bool: True если слот успешно выделен, False в противном случае
        """
        try:
            increment_host_config_count(host_name)
            logger.info(f"Allocated config slot to host '{host_name}'")
            return True
        except Exception as e:
            logger.error(f"Error allocating config to host '{host_name}': {e}")
            return False
    
    @staticmethod
    def release_config_from_host(host_name: str) -> bool:
        """
        Освобождает слот конфигурации на указанном хосте.
        
        Args:
            host_name: Имя хоста
            
        Returns:
            bool: True если слот успешно освобожден, False в противном случае
        """
        try:
            decrement_host_config_count(host_name)
            logger.info(f"Released config slot from host '{host_name}'")
            return True
        except Exception as e:
            logger.error(f"Error releasing config from host '{host_name}': {e}")
            return False
    
    @staticmethod
    def get_load_statistics() -> list[Dict]:
        """
        Возвращает статистику загрузки всех хостов.
        
        Returns:
            list[Dict]: Список хостов с их статистикой загрузки
        """
        try:
            return get_hosts_load_status()
        except Exception as e:
            logger.error(f"Error getting load statistics: {e}")
            return []
    
    @staticmethod
    def update_limits(host_name: Optional[str] = None, max_configs: Optional[int] = None) -> bool:
        """
        Обновляет лимиты конфигураций для хостов.
        
        Args:
            host_name: Имя хоста (если None, обновляет для всех хостов)
            max_configs: Новый лимит конфигураций
            
        Returns:
            bool: True если лимиты успешно обновлены, False в противном случае
        """
        try:
            update_host_limits(host_name, max_configs)
            if host_name:
                logger.info(f"Updated limits for host '{host_name}' to {max_configs}")
            else:
                logger.info(f"Updated limits for all hosts to {max_configs}")
            return True
        except Exception as e:
            logger.error(f"Error updating limits: {e}")
            return False
    
    @staticmethod
    def synchronize_counters() -> bool:
        """
        Синхронизирует счетчики конфигураций с реальными данными в базе.
        
        Returns:
            bool: True если синхронизация прошла успешно, False в противном случае
        """
        try:
            sync_host_config_counts()
            logger.info("Successfully synchronized host config counters")
            return True
        except Exception as e:
            logger.error(f"Error synchronizing counters: {e}")
            return False
    
    @staticmethod
    def check_host_availability(host_name: str) -> bool:
        """
        Проверяет, доступен ли хост для новых конфигураций.
        
        Args:
            host_name: Имя хоста
            
        Returns:
            bool: True если хост доступен, False если на лимите
        """
        try:
            load_stats = get_hosts_load_status()
            for host in load_stats:
                if host['host_name'] == host_name:
                    return host['current_configs'] < host['max_configs']
            return False
        except Exception as e:
            logger.error(f"Error checking host availability for '{host_name}': {e}")
            return False
    
    @staticmethod
    def get_host_load_percentage(host_name: str) -> float:
        """
        Возвращает процент загрузки указанного хоста.
        
        Args:
            host_name: Имя хоста
            
        Returns:
            float: Процент загрузки (0.0 - 100.0)
        """
        try:
            load_stats = get_hosts_load_status()
            for host in load_stats:
                if host['host_name'] == host_name:
                    return host['load_percentage']
            return 0.0
        except Exception as e:
            logger.error(f"Error getting load percentage for '{host_name}': {e}")
            return 0.0
    
    @staticmethod
    def is_any_host_available() -> bool:
        """
        Проверяет, есть ли хотя бы один доступный хост.
        
        Returns:
            bool: True если есть доступные хосты, False если все на лимите
        """
        try:
            host = get_best_available_host()
            return host is not None
        except Exception as e:
            logger.error(f"Error checking host availability: {e}")
            return False
    
    @staticmethod
    def get_total_capacity() -> Dict[str, int]:
        """
        Возвращает общую информацию о мощности всех хостов.
        
        Returns:
            Dict: Словарь с общей статистикой
        """
        try:
            load_stats = get_hosts_load_status()
            total_configs = sum(host['current_configs'] for host in load_stats)
            total_capacity = sum(host['max_configs'] for host in load_stats)
            available_slots = total_capacity - total_configs
            
            return {
                'total_configs': total_configs,
                'total_capacity': total_capacity,
                'available_slots': available_slots,
                'hosts_count': len(load_stats),
                'load_percentage': round((total_configs / total_capacity * 100) if total_capacity > 0 else 0, 2)
            }
        except Exception as e:
            logger.error(f"Error getting total capacity: {e}")
            return {
                'total_configs': 0,
                'total_capacity': 0,
                'available_slots': 0,
                'hosts_count': 0,
                'load_percentage': 0.0
            }
