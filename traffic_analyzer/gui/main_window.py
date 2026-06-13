"""Главное окно DRAKKAR NetScanner."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QAction, QDesktopServices
from PyQt6.QtWidgets import (
    QFileDialog,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from traffic_analyzer.core.capture_engine import (
    NPCAP_DOWNLOAD_URL,
    PacketCaptureThread,
    npcap_установлен,
    получить_интерфейсы,
)
from traffic_analyzer.core.parser import PacketRecord
from traffic_analyzer.gui.styles import ТЕМНАЯ_ТЕМА
from traffic_analyzer.gui.widgets import PacketTableModel, ProtocolPieWidget, TrafficGraphWidget


class MainWindow(QMainWindow):
    """Основное окно приложения с панелью управления, таблицей и графиками."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DRAKKAR NetScanner")
        self.resize(1440, 900)
        self.setStyleSheet(ТЕМНАЯ_ТЕМА)

        self.capture_thread: PacketCaptureThread | None = None
        self.total_packets = 0
        self.total_bytes = 0

        self.model = PacketTableModel(self)
        self._npcap_warning_shown = False
        self._build_ui()
        self._refresh_interfaces()
        self._refresh_stats()
        self._show_npcap_warning_if_needed()

    def closeEvent(self, event) -> None:
        """Останавливает захват перед закрытием окна."""

        self._stop_thread()
        event.accept()

    def _build_ui(self) -> None:
        self._build_menu()
        central_widget = QWidget()
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(14, 14, 14, 10)
        root_layout.setSpacing(10)

        root_layout.addWidget(self._build_toolbar())
        root_layout.addWidget(self._build_table(), 3)
        root_layout.addWidget(self._build_bottom_area(), 2)
        self.setCentralWidget(central_widget)
        self.statusBar().showMessage("Готов к захвату")

    def _build_menu(self) -> None:
        help_menu = self.menuBar().addMenu("Справка")

        download_npcap_action = QAction("Скачать Npcap", self)
        download_npcap_action.triggered.connect(self._open_npcap_download_page)
        help_menu.addAction(download_npcap_action)

        about_action = QAction("О программе", self)
        about_action.triggered.connect(self._show_about_dialog)
        help_menu.addAction(about_action)

    def _build_toolbar(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("верхняяПанель")
        grid = QGridLayout(panel)
        grid.setContentsMargins(14, 12, 14, 12)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)

        title = QLabel("DRAKKAR NetScanner")
        title.setObjectName("заголовок")
        subtitle = QLabel("Визуализация и интерактивный анализ сетевого трафика")
        subtitle.setObjectName("подпись")

        self.interface_box = SafeComboBox()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(
            "BPF-фильтр: tcp, udp, icmp, port 53, host 8.8.8.8"
        )

        self.start_button = QPushButton("Старт")
        self.start_button.setObjectName("старт")
        self.stop_button = QPushButton("Стоп")
        self.stop_button.setObjectName("стоп")
        self.clear_button = QPushButton("Очистить")
        self.export_button = QPushButton("Экспорт в PCAP")
        self.stop_button.setEnabled(False)

        self.stats_label = QLabel()
        self.stats_label.setObjectName("статистика")

        self.start_button.clicked.connect(self._start_capture)
        self.stop_button.clicked.connect(self._stop_capture)
        self.clear_button.clicked.connect(self._clear)
        self.export_button.clicked.connect(self._export_pcap)

        grid.addWidget(title, 0, 0, 1, 2)
        grid.addWidget(subtitle, 1, 0, 1, 2)
        grid.addWidget(QLabel("Интерфейс"), 0, 2)
        grid.addWidget(self.interface_box, 1, 2)
        grid.addWidget(QLabel("Фильтр"), 0, 3)
        grid.addWidget(self.filter_edit, 1, 3)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        for button in (
            self.start_button,
            self.stop_button,
            self.clear_button,
            self.export_button,
        ):
            buttons.addWidget(button)
        buttons.addStretch(1)

        grid.addLayout(buttons, 2, 0, 1, 4)
        grid.addWidget(self.stats_label, 2, 4)
        grid.setColumnStretch(3, 1)
        return panel

    def _build_table(self) -> QTableView:
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 190)
        self.table.setColumnWidth(3, 190)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(5, 80)
        self.table.selectionModel().selectionChanged.connect(self._show_packet_details)
        return self.table

    def _build_bottom_area(self) -> QSplitter:
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["Поле", "Значение"])
        self.detail_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.detail_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        charts_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.traffic_graph = TrafficGraphWidget()
        self.protocol_pie = ProtocolPieWidget()
        charts_splitter.addWidget(self.traffic_graph)
        charts_splitter.addWidget(self.protocol_pie)
        charts_splitter.setSizes([580, 420])

        splitter.addWidget(self.detail_tree)
        splitter.addWidget(charts_splitter)
        splitter.setSizes([420, 980])
        return splitter

    def _refresh_interfaces(self) -> None:
        self.interface_box.clear()
        interfaces = получить_интерфейсы()
        for interface in interfaces:
            tooltip_parts = [f"Устройство: {interface.имя}"]
            if interface.mac:
                tooltip_parts.append(f"MAC: {interface.mac}")
            if interface.адреса:
                tooltip_parts.append(f"Адреса: {', '.join(interface.адреса)}")
            self.interface_box.addItem(interface.подпись, interface.имя)
            self.interface_box.setItemData(
                self.interface_box.count() - 1,
                "\n".join(tooltip_parts),
                Qt.ItemDataRole.ToolTipRole,
            )
        if not interfaces:
            self.statusBar().showMessage("Сетевые интерфейсы не найдены")
            self.start_button.setEnabled(False)

    def _start_capture(self) -> None:
        if not npcap_установлен():
            self._show_npcap_warning(force=True)
            return

        interface = self.interface_box.currentData() or self.interface_box.currentText()
        if not interface:
            QMessageBox.warning(self, "Нет интерфейса", "Выберите сетевой интерфейс для захвата.")
            return

        self.capture_thread = PacketCaptureThread(
            интерфейс=interface,
            bpf_фильтр=self.filter_edit.text(),
        )
        self.capture_thread.packet_captured.connect(self._add_packet)
        self.capture_thread.capture_error.connect(self._show_capture_error)
        self.capture_thread.capture_status.connect(self.statusBar().showMessage)
        self.capture_thread.finished.connect(self._capture_finished)
        self.capture_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.interface_box.setEnabled(False)
        self.filter_edit.setEnabled(False)

    def _stop_capture(self) -> None:
        self._stop_thread()
        self._capture_finished()

    def _stop_thread(self) -> None:
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait(2500)

    def _capture_finished(self) -> None:
        self.start_button.setEnabled(bool(self.interface_box.count()))
        self.stop_button.setEnabled(False)
        self.interface_box.setEnabled(True)
        self.filter_edit.setEnabled(True)

    def _add_packet(self, record: PacketRecord, _raw_packet: object) -> None:
        self.model.добавить(record)
        self.total_packets += 1
        self.total_bytes += record.длина
        self.traffic_graph.добавить_пакет(record)
        self.protocol_pie.добавить_пакет(record)
        self._refresh_stats()

        scrollbar = self.table.verticalScrollBar()
        if scrollbar.value() >= scrollbar.maximum() - 3:
            self.table.scrollToBottom()

    def _show_packet_details(self) -> None:
        selected_rows = self.table.selectionModel().selectedRows()
        self.detail_tree.clear()
        if not selected_rows:
            return

        record = self.model.запись(selected_rows[0].row())
        if record is None:
            return

        for layer in record.слои:
            layer_item = QTreeWidgetItem([layer["имя"], ""])
            self.detail_tree.addTopLevelItem(layer_item)
            for field_name, value in layer["поля"].items():
                layer_item.addChild(QTreeWidgetItem([field_name, str(value)]))
            layer_item.setExpanded(True)

    def _clear(self) -> None:
        self.model.очистить()
        self.detail_tree.clear()
        self.traffic_graph.очистить()
        self.protocol_pie.очистить()
        self.total_packets = 0
        self.total_bytes = 0
        if self.capture_thread:
            self.capture_thread.очистить_буфер()
        self._refresh_stats()
        self.statusBar().showMessage("Данные очищены")

    def _export_pcap(self) -> None:
        if not self.capture_thread:
            QMessageBox.information(self, "Экспорт", "Нет захваченных пакетов для экспорта.")
            return

        file_path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Экспортировать захват",
            str(Path.home() / "drakkar_capture.pcap"),
            "PCAP (*.pcap);;Все файлы (*)",
        )
        if not file_path:
            return

        saved_count = self.capture_thread.экспортировать_pcap(file_path)
        QMessageBox.information(
            self,
            "Экспорт завершен",
            f"Сохранено пакетов: {saved_count}\nФайл: {file_path}",
        )

    def _show_capture_error(self, message: str) -> None:
        QMessageBox.critical(self, "Ошибка захвата", message)
        self.statusBar().showMessage("Ошибка захвата")
        self._capture_finished()

    def _refresh_stats(self) -> None:
        megabytes = self.total_bytes / (1024 * 1024)
        self.stats_label.setText(
            f"Пакетов: {self.total_packets} | Данных: {megabytes:.2f} МБ"
        )

    def _show_npcap_warning_if_needed(self) -> None:
        if not npcap_установлен():
            self._show_npcap_warning(force=False)

    def _show_npcap_warning(self, force: bool) -> None:
        if self._npcap_warning_shown and not force:
            return
        self._npcap_warning_shown = True

        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setWindowTitle("Требуется Npcap")
        dialog.setText("Для работы DRAKKAR NetScanner необходимо установить Npcap.")
        dialog.setInformativeText(
            "Npcap предоставляет драйвер захвата пакетов для Windows. "
            "Без него приложение не сможет читать сетевой трафик с интерфейсов."
        )
        dialog.setDetailedText(f"Официальная ссылка для загрузки: {NPCAP_DOWNLOAD_URL}")
        open_button = dialog.addButton("Открыть страницу загрузки", QMessageBox.ButtonRole.AcceptRole)
        dialog.addButton("Продолжить без захвата", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()

        if dialog.clickedButton() == open_button:
            self._open_npcap_download_page()

    def _open_npcap_download_page(self) -> None:
        QDesktopServices.openUrl(QUrl(NPCAP_DOWNLOAD_URL))

    def _show_about_dialog(self) -> None:
        QMessageBox.information(
            self,
            "О программе",
            "DRAKKAR NetScanner\n"
            "Система визуализации и интерактивного анализа сетевого трафика.",
        )


class SafeComboBox(QComboBox):
    """QComboBox с прокруткой колесом мыши только при наличии фокуса."""

    def wheelEvent(self, event) -> None:
        if self.hasFocus():
            super().wheelEvent(event)
        else:
            event.ignore()
