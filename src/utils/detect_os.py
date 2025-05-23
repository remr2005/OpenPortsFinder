"""
Детектор операционной системы
"""

from collections import defaultdict
from difflib import SequenceMatcher
from typing import Dict, Tuple

# Расширенная база данных отпечатков ОС
OS_FINGERPRINTS = {
    "Windows 10/11": {
        "ttl": 128,
        "window": [8192, 64240, 65535],
        "window_scaling": [7, 8],
        "options": ["MSS", "NOP", "NOP", "SACK", "NOP", "WScale"],
        "options_order": True,
        "mss_values": [1460],
        "df_flag": True,
        "response_to_fin": False,
        "response_to_null": False,
        "ip_id_behavior": "random",
        "timestamp": False,
        "ecn_support": False,
        "quirks": {"bad_checksum": False, "zero_window_probe": True},
    },
    "Linux (ядро 5.x)": {
        "ttl": 64,
        "window": [5840, 5720, 29200],
        "window_scaling": [6, 7],
        "options": ["MSS", "SACK", "TS", "NOP", "WScale"],
        "options_order": True,
        "mss_values": [1460],
        "df_flag": True,
        "response_to_fin": True,
        "response_to_null": True,
        "ip_id_behavior": "random",
        "timestamp": True,
        "ecn_support": True,
        "quirks": {"bad_checksum": False, "zero_window_probe": False},
    },
    # ... другие ОС
}


async def extract_packet_features(response) -> Dict:
    """Извлечение всех возможных признаков из пакета"""
    features = defaultdict(lambda: None)

    if not response or not response.haslayer(TCP):
        return features

    # Базовые TCP/IP параметры
    features["ttl"] = response.ttl
    features["window"] = response.getlayer(TCP).window
    features["flags"] = response.getlayer(TCP).flags

    # TCP опции
    options = []
    for opt in response.getlayer(TCP).options:
        if isinstance(opt, tuple):
            options.append(opt[0])
            if opt[0] == "MSS":
                features["mss"] = opt[1]
            elif opt[0] == "WScale":
                features["wscale"] = opt[1]
            elif opt[0] == "Timestamp":
                features["timestamp"] = True
            elif opt[0] == "SAckOK":
                features["sack"] = True
            elif opt[0] == "ECN":
                features["ecn"] = True

    features["options"] = options
    features["options_str"] = ",".join(options)

    # IP параметры
    if response.haslayer(IP):
        features["df_flag"] = response.getlayer(IP).flags.DF
        features["ip_id"] = response.getlayer(IP).id

    return features


def calculate_feature_similarity(
    observed: Dict, reference: Dict, feature: str, weight: float = 1.0
) -> float:
    """Расчет коэффициента схожести для конкретного признака"""
    if feature not in reference:
        return 0.0

    obs_val = observed.get(feature)
    ref_val = reference[feature]

    # Для числовых значений
    if isinstance(ref_val, (int, float, list)):
        if isinstance(ref_val, list):
            if obs_val in ref_val:
                return weight
            # Для window_scaling ищем ближайшее значение
            if feature == "window_scaling":
                closest = min(ref_val, key=lambda x: abs(x - obs_val))
                diff = 1 - min(abs(obs_val - closest) / max(1, closest), 1.0)
                return diff * weight
            return 0.0
        else:
            return weight if obs_val == ref_val else 0.0

    # Для булевых значений
    elif isinstance(ref_val, bool):
        return weight if obs_val == ref_val else 0.0

    # Для строк (TCP options)
    elif feature == "options_str":
        return SequenceMatcher(None, obs_val, ref_val).ratio() * weight

    # Для списков (порядок опций)
    elif feature == "options" and reference.get("options_order", False):
        if len(obs_val) != len(ref_val):
            return 0.0
        return weight if obs_val == ref_val else 0.0

    return 0.0


async def detect_os(response) -> Tuple[str, float, Dict]:
    """Определение ОС с максимальным количеством параметров"""
    if not response or not response.haslayer(TCP):
        return "Unknown OS", 0.0, {}

    observed = await extract_packet_features(response)
    best_match = ("Unknown OS", 0.0, {})

    # Веса для различных признаков (сумма = 1.0)
    feature_weights = {
        "ttl": 0.15,
        "window": 0.15,
        "window_scaling": 0.05,
        "options_str": 0.2,
        "options": 0.1,
        "mss": 0.05,
        "df_flag": 0.05,
        "response_to_fin": 0.05,
        "response_to_null": 0.05,
        "timestamp": 0.05,
        "ecn_support": 0.05,
        "quirks": 0.05,
    }

    for os_name, os_data in OS_FINGERPRINTS.items():
        total_similarity = 0.0

        # Считаем схожесть по всем параметрам
        for feature, weight in feature_weights.items():
            if feature == "quirks":
                # Особые случаи обрабатываем отдельно
                quirk_similarity = 0.0
                for quirk, value in os_data.get("quirks", {}).items():
                    if observed.get(quirk) == value:
                        quirk_similarity += weight / len(os_data["quirks"])
                total_similarity += quirk_similarity
            else:
                total_similarity += calculate_feature_similarity(
                    observed, os_data, feature, weight
                )

        # Нормализуем до 1.0
        total_similarity = min(total_similarity, 1.0)

        if total_similarity > best_match[1]:
            best_match = (
                os_name,
                total_similarity,
                {
                    "matched_features": [
                        f
                        for f in feature_weights
                        if calculate_feature_similarity(observed, os_data, f, 1.0) > 0.8
                    ]
                },
            )

    # Возвращаем только если уверенность > 65%
    if best_match[1] > 0.65:
        return best_match
    return "Unknown OS", 0.0, {}
