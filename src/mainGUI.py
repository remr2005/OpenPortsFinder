import asyncio
import ipaddress
import sys

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
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
    "S": syn,
    "F": fin,
    "N": null,
    "X": xmas,
    "T": tcp_scan,
    "A": ack,
    "U": udp,
    "ID": idle,
    "SP": source_port_manipulation,
    "FR": fragmented_tcp_scan,
    "IE": icmp_echo_scan,
    "IM": icmp_address_mask_scan,
    "IT": icmp_timestamp_scan,
    "CVE": scan_network,
}


class ScanWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python OpenPortsFinder GUI")

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # --- Target input
        target_layout = QHBoxLayout()
        target_label = QLabel("Цель:")
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(
            "192.168.1.1 / 192.168.1.0/24 / 192.168.1.1,2"
        )
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.target_edit)
        self.layout.addLayout(target_layout)

        # --- Scan type combo
        scan_type_layout = QHBoxLayout()
        scan_type_label = QLabel("Тип сканирования:")
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(SCAN_TYPES.keys())
        scan_type_layout.addWidget(scan_type_label)
        scan_type_layout.addWidget(self.scan_type_combo)
        self.layout.addLayout(scan_type_layout)

        # --- Ports input (only visible for some scans)
        self.ports_widget = QWidget()
        self.ports_layout = QHBoxLayout()
        self.ports_widget.setLayout(self.ports_layout)
        ports_label = QLabel("Порты:")
        self.ports_edit = QLineEdit()
        self.ports_edit.setPlaceholderText("80 / 80,443 / 1-100")
        self.ports_layout.addWidget(ports_label)
        self.ports_layout.addWidget(self.ports_edit)
        self.layout.addWidget(self.ports_widget)

        # --- Checkboxes
        self.detect_os_cb = QCheckBox("Определение ОС")
        self.send_rst_cb = QCheckBox("Посылать RST")
        self.layout.addWidget(self.detect_os_cb)
        self.layout.addWidget(self.send_rst_cb)

        # --- zombi-ip (for idle scan)
        self.zombi_widget = QWidget()
        zombi_layout = QHBoxLayout()
        self.zombi_widget.setLayout(zombi_layout)
        zombi_label = QLabel("Zombi IP:")
        self.zombi_edit = QLineEdit()
        self.zombi_edit.setPlaceholderText("IP зомби хоста для idle скана")
        zombi_layout.addWidget(zombi_label)
        zombi_layout.addWidget(self.zombi_edit)
        self.layout.addWidget(self.zombi_widget)

        # --- false port (for source port manipulation)
        self.false_port_widget = QWidget()
        false_port_layout = QHBoxLayout()
        self.false_port_widget.setLayout(false_port_layout)
        false_port_label = QLabel("Ложный порт:")
        self.false_port_edit = QLineEdit()
        self.false_port_edit.setPlaceholderText("Ложный порт (по умолчанию 53)")
        self.false_port_edit.setText("53")
        false_port_layout.addWidget(false_port_label)
        false_port_layout.addWidget(self.false_port_edit)
        self.layout.addWidget(self.false_port_widget)

        # --- Start button
        self.start_btn = QPushButton("Начать сканирование")
        self.layout.addWidget(self.start_btn)

        # --- Output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.layout.addWidget(self.output)

        # Connections
        self.scan_type_combo.currentTextChanged.connect(self.on_scan_type_changed)
        self.start_btn.clicked.connect(self.on_start)

        # Изначально обновим видимость
        self.on_scan_type_changed(self.scan_type_combo.currentText())

    def on_scan_type_changed(self, scan_type):
        # Порты нужны не для ICMP, CVE, idle (исправлено: для ID показываем порты)
        show_ports = scan_type not in [
            "IE",
            "IM",
            "IT",
            "CVE",
        ]  # убрал "ID" из списка скрытия портов
        for i in range(self.ports_layout.count()):
            self.ports_layout.itemAt(i).widget().setVisible(show_ports)
        self.ports_layout.setEnabled(show_ports)

        # zombi-ip только для idle
        self.zombi_edit.parentWidget().setVisible(scan_type == "ID")

        # ложный порт только для source port manipulation и idle
        self.false_port_edit.parentWidget().setVisible(scan_type in ["SP", "ID"])

        # detect_os и send_rst только для SYN
        self.detect_os_cb.setVisible(scan_type == "S")
        self.send_rst_cb.setVisible(scan_type == "S")

    def parse_ports(self, port_str):
        ports = []
        if not port_str:
            return ports
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    ports.extend(range(start, end + 1))
                except Exception:
                    continue
            else:
                try:
                    ports.append(int(part))
                except Exception:
                    continue
        return ports

    def parse_targets(self, target_str):
        targets = []
        for part in target_str.split(","):
            part = part.strip()
            if "/" in part:
                try:
                    network = ipaddress.ip_network(part, strict=False)
                    targets.extend([str(host) for host in network.hosts()])
                except Exception as e:
                    self.output.append(f"Ошибка парсинга сети: {part} ({e})")
            else:
                targets.append(part)
        return targets

    def log(self, text):
        self.output.append(text)

    def clear_log(self):
        self.output.clear()

    async def run_scan(self):
        self.clear_log()

        target_str = self.target_edit.text().strip()
        if not target_str:
            self.log("Ошибка: укажите цель сканирования")
            return

        scan_type = self.scan_type_combo.currentText()
        scan_func = SCAN_TYPES[scan_type]

        try:
            targets = self.parse_targets(target_str)
        except Exception as e:
            self.log(f"Ошибка парсинга целей: {e}")
            return

        dargs = []
        if scan_type == "ID":  # idle scan
            zombi_ip = self.zombi_edit.text().strip()
            if not zombi_ip:
                self.log("Ошибка: укажите IP зомби для idle скана")
                return
            dargs.append(zombi_ip)
        elif scan_type == "SP":  # source port manipulation
            false_port = self.false_port_edit.text().strip()
            if not false_port:
                false_port = "53"
            dargs.append(false_port)
        elif scan_type == "S":
            dargs = [self.send_rst_cb.isChecked(), self.detect_os_cb.isChecked()]

        self.log(f"Начинаем сканирование {target_str} с методом {scan_type}...")

        try:
            if scan_type in ["IE", "IM", "IT", "CVE"]:
                results = await async_mass_scan_ICMP(targets, scan_func)
            else:
                ports = self.parse_ports(self.ports_edit.text())
                if not ports:
                    self.log("Ошибка: укажите порты для сканирования")
                    return
                results = await async_mass_scan(targets, ports, scan_func, dargs)
        except Exception as e:
            self.log(f"Ошибка при сканировании: {e}")
            return

        if scan_type in ["IE", "IM", "IT"]:
            filtered = [r for r in results if r[1]]
        elif scan_func == "CVE":
            filtered = [(r, "") for r in results]
        else:
            filtered = [r for r in results if r[2]]

        if not filtered:
            self.log("Результаты сканирования пусты или все значения False")
        else:
            for line in filtered:
                if scan_type in ["IE", "IM", "IT", "CVE"]:
                    self.log(f"{line[0]} пингуется")
                else:
                    self.log(
                        f"{line[0]} порт {line[1]} открыт " + line[3]
                        if scan_type == "S"
                        else ""
                    )
                    # comment: )
        self.log("Сканирование завершено")

    def on_start(self):
        # Запускаем асинхронное сканирование
        asyncio.create_task(self.run_scan())


import qasync


def main():
    app = QApplication(sys.argv)
    window = ScanWindow()
    window.resize(700, 600)
    window.show()

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    with loop:
        loop.run_forever()


if __name__ == "__main__":
    main()
