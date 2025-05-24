"""
Функции напрямую не связанные со сканированием
"""

import asyncio


async def async_mass_scan(
    ip_list: list[str],
    port_list: list[int | str],
    scan_func: object,
    args: list | tuple = [],
):
    """
    Выполняет массовое асинхронное сканирование IP-адресов и портов с помощью указанной функции сканирования.

    Параметры:
        ip_list (list[str]): Список IP-адресов для сканирования, например ["192.168.1.1", "10.0.0.1"].
        port_list (list[int | str]): Список портов для сканирования, например [22, 80, 443].
        scan_func (coroutine): Асинхронная функция сканирования с сигнатурой scan_func(ip, port, *args).
        args (list | tuple, optional): Дополнительные позиционные аргументы для scan_func. По умолчанию пустой список.

    Возвращает:
        list[tuple]: Список кортежей (ip, port, is_open), где is_open — булево значение, указывающее открыт ли порт.
    """
    tasks = []
    for ip in ip_list:
        for port in port_list:
            task = asyncio.create_task(scan_func(ip, port, *args))
            tasks.append(task)

    results = await asyncio.gather(*tasks)
    return results


async def async_mass_scan_ICMP(
    ip_list: list[str],
    scan_func: object,
):
    """
    Выполняет массовое асинхронное сканирование IP-адресов с помощью ICMP-пинга.

    Параметры:
        ip_list (list[str]): Список IP-адресов для сканирования, например ["192.168.1.1", "10.0.0.1"].
        scan_func (coroutine): Асинхронная функция сканирования с сигнатурой scan_func(ip).

    Возвращает:
        list[tuple]: Список кортежей (ip, is_alive), где is_alive — булево значение, указывающее доступен ли IP.
    """
    tasks = []
    for ip in ip_list:
        task = asyncio.create_task(scan_func(ip))
        tasks.append(task)

    results = await asyncio.gather(*tasks)
    return results
