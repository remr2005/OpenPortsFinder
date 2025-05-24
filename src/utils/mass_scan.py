import asyncio


async def async_mass_scan(
    ip_list: list[str],
    port_list: list[int | str],
    scan_func: object,
):
    """
    Массовое асинхронное сканирование IP и портов.

    Параметры:
        - ip_list: список IP (например, ["192.168.1.1", "10.0.0.1"])
        - port_list: список портов (например, [22, 80, 443])
        - scan_funcs: список асинхронных функций сканирования (например, [syn_scan, tcp_scan])
        - max_concurrent: максимальное количество одновременных задач (по умолчанию 500)

    Возвращает:
        - Список кортежей (ip, port, is_open: bool)
    """
    tasks = []
    for ip in ip_list:
        for port in port_list:
            task = asyncio.create_task(scan_func(ip, port))
            tasks.append(task)

    results = await asyncio.gather(*tasks)
    return results
