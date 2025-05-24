import asyncio
import ipaddress
import sys
from typing import List

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from scans import (
    ack,
    fin,
    fragmented_tcp_scan,
    icmp_address_mask_scan,
    icmp_echo_scan,
    icmp_timestamp_scan,
    idle,
    null,
    scan_network,
    source_port_manipulation,
    syn,
    tcp_scan,
    udp,
    xmas,
)
from utils import async_mass_scan, async_mass_scan_ICMP

SCAN_TYPES = {
    "SYN": syn,
    "FIN": fin,
    "NULL": null,
    "XMAS": xmas,
    "TCP Connect": tcp_scan,
    "ACK": ack,
    "UDP": udp,
    "Idle": idle,
    "Source Port Manip": source_port_manipulation,
    "Fragmented TCP": fragmented_tcp_scan,
    "ICMP Echo": icmp_echo_scan,
    "ICMP Addr Mask": icmp_address_mask_scan,
    "ICMP Timestamp": icmp_timestamp_scan,
    "CVE Scan": scan_network,
}

ICMP_TYPES = {"ICMP Echo", "ICMP Addr Mask", "ICMP Timestamp", "CVE Scan"}


def parse_ports(port_str: str) -> List[int]:
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports


def parse_targets(target_str: str) -> List[str]:
    targets = []
    for part in target_str.split(","):
        if "/" in part:
            network = ipaddress.ip_network(part, strict=False)
            targets.extend([str(host) for host in network.hosts()])
        else:
            targets.append(part)
    return targets


class PortScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OpenPortsFinder GUI")
        self.setMinimumWidth(400)

        self.form = QFormLayout()

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Пример: 192.168.1.1, 192.168.1.0/24")
        self.form.addRow("Цель:", self.target_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Пример: 80,443,1000-1010")
        self.form.addRow("Порты:", self.port_input)

        self.scan_type = QComboBox()
        self.scan_type.addItems(SCAN_TYPES.keys())
        self.scan_type.currentTextChanged.connect(self.toggle_options)
        self.form.addRow("Тип сканирования:", self.scan_type)

        self.os_check = QCheckBox("Определение ОС")
        self.form.addRow("", self.os_check)

        self.rst_check = QCheckBox("Отправка RST")
        self.form.addRow("", self.rst_check)

        self.zombie_input = QLineEdit()
        self.zombie_input.setPlaceholderText("Zombie IP (для Idle скана)")
        self.form.addRow("Zombie IP:", self.zombie_input)

        self.false_port_input = QLineEdit()
        self.false_port_input.setPlaceholderText("Ложный порт (по умолчанию 53)")
        self.false_port_input.setText("53")
        self.form.addRow("Ложный порт:", self.false_port_input)

        self.run_button = QPushButton("Начать сканирование")
        self.run_button.clicked.connect(self.run_scan)

        vbox = QVBoxLayout()
        vbox.addLayout(self.form)
        vbox.addWidget(self.run_button)
        self.setLayout(vbox)

        self.toggle_options()

    def toggle_options(self):
        scan = self.scan_type.currentText()

        # Показываем/скрываем по типу сканирования
        is_icmp = scan in ICMP_TYPES
        is_idle = scan == "Idle"
        is_spm = scan == "Source Port Manip"
        is_syn = scan == "SYN"

        self.port_input.setVisible(not is_icmp)
        self.form.labelForField(self.port_input).setVisible(not is_icmp)

        self.os_check.setVisible(is_syn)
        self.rst_check.setVisible(is_syn)

        self.zombie_input.setVisible(is_idle)
        self.form.labelForField(self.zombie_input).setVisible(is_idle)

        self.false_port_input.setVisible(is_spm)
        self.form.labelForField(self.false_port_input).setVisible(is_spm)

    def run_scan(self):
        asyncio.create_task(self._run_scan())

    async def _run_scan(self):
        target = self.target_input.text().strip()
        ports_str = self.port_input.text().strip()
        scan_key = self.scan_type.currentText()
        detect_os = self.os_check.isChecked()
        send_rst = self.rst_check.isChecked()
        zombi_ip = self.zombie_input.text().strip()
        false_port = self.false_port_input.text().strip()

        if not target:
            QMessageBox.warning(self, "Ошибка", "Цель не указана")
            return

        try:
            targets = parse_targets(target)
            scan_func = SCAN_TYPES[scan_key]
            dargs = []

            if scan_key == "SYN":
                dargs = [send_rst, detect_os]
            elif scan_key == "Idle":
                dargs = [zombi_ip]
            elif scan_key == "Source Port Manip":
                dargs = [false_port]

            if scan_key in ICMP_TYPES:
                await async_mass_scan_ICMP(targets, scan_func)
            else:
                if not ports_str:
                    QMessageBox.warning(self, "Ошибка", "Порты не указаны")
                    return
                ports = parse_ports(ports_str)
                await async_mass_scan(targets, ports, scan_func, dargs)

            QMessageBox.information(self, "Готово", "Сканирование завершено")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = PortScannerApp()
    scanner.show()
    asyncio.run(app.exec())
