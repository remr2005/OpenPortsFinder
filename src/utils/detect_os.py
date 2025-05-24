"""
Улучшенный детектор операционной системы по сетевым отпечаткам
"""

from collections import defaultdict
from difflib import SequenceMatcher
from typing import Dict, List, Tuple

from scapy.all import IP, TCP

# Расширенная база данных отпечатков ОС с весами признаков
OS_DATABASE = {
    "Windows 10/11": {
        "features": {
            "initial_ttl": (128, 0.15),
            "window_size": ([8192, 64240, 65535], 0.15),
            "tcp_options": (["MSS", "NOP", "NOP", "SACK", "NOP", "WScale"], 0.25),
            "options_order": (True, 0.1),
            "window_scaling": ([7, 8], 0.05),
            "mss_value": ([1460], 0.05),
            "df_flag": (True, 0.05),
            "timestamp": (False, 0.05),
            "ecn_support": (False, 0.05),
            "quirks": ({"zero_window_probe": True}, 0.1),
        }
    },
    "Linux (ядро 5.x)": {
        "features": {
            "initial_ttl": (64, 0.15),
            "window_size": ([5840, 5720, 29200], 0.15),
            "tcp_options": (["MSS", "SACK", "TS", "NOP", "WScale"], 0.25),
            "options_order": (True, 0.1),
            "window_scaling": ([6, 7], 0.05),
            "mss_value": ([1460], 0.05),
            "df_flag": (True, 0.05),
            "timestamp": (True, 0.05),
            "ecn_support": (True, 0.05),
            "quirks": ({"zero_window_probe": False}, 0.1),
        }
    },
    "macOS 12+": {
        "features": {
            "initial_ttl": (64, 0.15),
            "window_size": ([65535], 0.15),
            "tcp_options": (["MSS", "NOP", "WScale", "NOP", "NOP", "SACK"], 0.25),
            "options_order": (True, 0.1),
            "window_scaling": ([6], 0.05),
            "mss_value": ([1460], 0.05),
            "df_flag": (True, 0.05),
            "timestamp": (True, 0.05),
            "ecn_support": (True, 0.05),
            "quirks": ({"zero_window_probe": False}, 0.1),
        }
    },
}


async def extract_features(response) -> Dict:
    """
    Извлекает сетевые признаки из пакета TCP/IP для дальнейшей идентификации ОС.

    Args:
        response: Объект пакета (Scapy), содержащий сетевой ответ.

    Returns:
        Dict: Словарь с выявленными признаками и их значениями,
              включая TTL, размер окна, TCP опции, флаги и особенности.
    """
    features = defaultdict(lambda: None)

    if not response or not response.haslayer(TCP):
        return features

    try:
        # Базовые параметры IP
        if response.haslayer(IP):
            features["initial_ttl"] = response.ttl
            features["df_flag"] = bool(response.getlayer(IP).flags.DF)
            features["ip_id"] = response.getlayer(IP).id

        # Параметры TCP
        tcp = response.getlayer(TCP)
        features["window_size"] = tcp.window
        features["flags"] = tcp.flags

        # Анализ TCP опций
        options = []
        for opt in tcp.options:
            if isinstance(opt, tuple):
                opt_name, opt_value = opt[0], opt[1] if len(opt) > 1 else None
                options.append(opt_name)

                if opt_name == "MSS":
                    features["mss_value"] = opt_value
                elif opt_name == "WScale":
                    features["window_scaling"] = opt_value
                elif opt_name == "Timestamp":
                    features["timestamp"] = True
                elif opt_name == "SAckOK":
                    features["sack"] = True
                elif opt_name == "ECN":
                    features["ecn_support"] = True

        features["tcp_options"] = options
        features["options_str"] = ",".join(options)

    except Exception as e:
        print(f"Ошибка при извлечении признаков: {e}")

    return features


def calculate_match_score(observed: Dict, os_profile: Dict) -> float:
    """
    Сравнивает наблюдаемые признаки с профилем ОС и вычисляет коэффициент совпадения.

    Args:
        observed (Dict): Словарь с наблюдаемыми признаками из пакета.
        os_profile (Dict): Профиль ОС с ожидаемыми значениями и весами признаков.

    Returns:
        float: Нормализованный коэффициент совпадения в диапазоне [0.0, 1.0],
               где 1.0 — полное совпадение.
    """
    total_score = 0.0
    max_possible_score = 0.0

    for feature, (expected_value, weight) in os_profile["features"].items():
        observed_value = observed.get(feature)
        max_possible_score += weight

        if observed_value is None:
            continue

        # Для числовых значений
        if isinstance(expected_value, (int, float)):
            if observed_value == expected_value:
                total_score += weight

        # Для списков значений
        elif isinstance(expected_value, list):
            if observed_value in expected_value:
                total_score += weight
            elif feature in ["window_size", "window_scaling"]:
                # Частичное совпадение для размеров окна
                closest = min(expected_value, key=lambda x: abs(x - observed_value))
                similarity = 1 - min(abs(observed_value - closest) / max(1, closest), 1)
                total_score += weight * similarity

        # Для строк (TCP options)
        elif feature == "options_str":
            similarity = SequenceMatcher(
                None, observed_value, ",".join(expected_value)
            ).ratio()
            total_score += weight * similarity

        # Для булевых значений
        elif isinstance(expected_value, bool):
            if observed_value == expected_value:
                total_score += weight

        # Для особенностей (quirks)
        elif feature == "quirks":
            quirk_matches = 0
            for quirk, quirk_value in expected_value.items():
                if observed.get(quirk) == quirk_value:
                    quirk_matches += 1
            total_score += weight * (quirk_matches / max(1, len(expected_value)))

    return (total_score / max_possible_score) if max_possible_score > 0 else 0.0


async def detect_os(response) -> List[Tuple[str, float]]:
    """
    Определяет наиболее вероятные операционные системы по сетевому ответу на SYN-запрос.

    Args:
        response: Объект пакета (Scapy) с ответом на TCP SYN.

    Returns:
        List[Tuple[str, float]]: Отсортированный список кортежей (название ОС,
                                 относительная вероятность совпадения в диапазоне [0.0, 1.0]).
                                 Если совпадений нет, возвращает [("Unknown OS", 0.0)].
    """
    if not response or not response.haslayer(TCP):
        return [("Unknown OS", 0.0)]

    observed_features = await extract_features(response)
    results = []

    for os_name, os_profile in OS_DATABASE.items():
        score = calculate_match_score(observed_features, os_profile)
        if score > 0:  # Игнорируем нулевые совпадения
            results.append((os_name, round(score * 100, 2)))

    # Сортируем по убыванию процента совпадения
    results.sort(key=lambda x: x[1], reverse=True)
    max_scr = max([i[1] for i in results])
    results = [(i[0], i[1] / max_scr) for i in results]

    # Если ничего не найдено, возвращаем Unknown
    return results if results else [("Unknown OS", 0.0)]
