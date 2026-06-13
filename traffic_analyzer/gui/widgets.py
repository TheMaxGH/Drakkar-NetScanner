"""Кастомные виджеты и модели интерфейса DRAKKAR NetScanner."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass

import pyqtgraph as pg
from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QColor, QPainter, QPen
from PyQt6.QtWidgets import QLabel, QSizePolicy, QVBoxLayout, QWidget

from traffic_analyzer.core.parser import PacketRecord


class PacketTableModel(QAbstractTableModel):
    """Производительная модель таблицы для десятков тысяч пакетов."""

    заголовки = (
        "№",
        "Время",
        "Источник",
        "Назначение",
        "Протокол",
        "Длина",
        "Информация",
    )

    def __init__(self, родитель: QWidget | None = None) -> None:
        super().__init__(родитель)
        self._записи: list[PacketRecord] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._записи)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.заголовки)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        запись = self._записи[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return запись.как_строка(index.column())
        if role == Qt.ItemDataRole.ForegroundRole:
            return QColor(_цвет_протокола(запись.протокол))
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in {0, 5}:
            return Qt.AlignmentFlag.AlignCenter
        return None

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.заголовки[section]
        return None

    def добавить(self, запись: PacketRecord) -> None:
        """Добавляет запись без полного сброса модели."""

        строка = len(self._записи)
        self.beginInsertRows(QModelIndex(), строка, строка)
        self._записи.append(запись)
        self.endInsertRows()

    def очистить(self) -> None:
        """Удаляет все строки таблицы."""

        self.beginResetModel()
        self._записи.clear()
        self.endResetModel()

    def запись(self, строка: int) -> PacketRecord | None:
        """Возвращает запись по номеру строки."""

        if 0 <= строка < len(self._записи):
            return self._записи[строка]
        return None

    def все_записи(self) -> list[PacketRecord]:
        """Возвращает копию списка записей для экспорта статистики."""

        return list(self._записи)


@dataclass(slots=True)
class TrafficPoint:
    """Одна точка временного ряда интенсивности трафика."""

    секунда: int
    количество: int


class TrafficGraphWidget(QWidget):
    """Интерактивный график пакетов в секунду."""

    def __init__(self, родитель: QWidget | None = None) -> None:
        super().__init__(родитель)
        self._точки: deque[TrafficPoint] = deque(maxlen=120)
        self._счетчик_секунд: Counter[int] = Counter()
        self.setMinimumHeight(260)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 4)
        layout.setSpacing(6)
        self.подпись = QLabel("Интенсивность трафика, пакетов/с")
        self.график = pg.PlotWidget()
        self.график.setMinimumHeight(220)
        self.график.setBackground("#0d1116")
        self.график.showGrid(x=True, y=True, alpha=0.25)
        self.график.setLabel("left", "Пакеты/с")
        self.график.setLabel("bottom", "Секунды")
        self.график.getAxis("left").setTextPen("#a9b8c4")
        self.график.getAxis("bottom").setTextPen("#a9b8c4")
        self.график.getAxis("left").setWidth(54)
        self.график.getAxis("bottom").setHeight(34)
        self.график.setMouseEnabled(x=True, y=False)
        self.график.setMenuEnabled(False)
        self.график.disableAutoRange(axis="x")
        self.график.disableAutoRange(axis="y")
        self.график.setLimits(xMin=0, yMin=0)
        self.график.setYRange(0, 5, padding=0)
        self.график.setXRange(0, 60, padding=0)
        self._кривая = self.график.plot(
            pen=pg.mkPen("#3fa7ff", width=2),
            symbol="o",
            symbolSize=5,
            symbolBrush="#3fa7ff",
        )
        layout.addWidget(self.подпись)
        layout.addWidget(self.график, 1)

    def добавить_пакет(self, запись: PacketRecord) -> None:
        """Обновляет временной ряд при поступлении пакета."""

        self._счетчик_секунд[запись.метка_секунды] += 1
        self._пересчитать_точки()
        self._обновить()

    def очистить(self) -> None:
        """Сбрасывает график интенсивности."""

        self._точки.clear()
        self._счетчик_секунд.clear()
        self._кривая.setData([], [])
        self.график.setYRange(0, 5, padding=0)
        self.график.setXRange(0, 60, padding=0)

    def _пересчитать_точки(self) -> None:
        последние = sorted(self._счетчик_секунд.items())[-120:]
        self._точки = deque(
            (TrafficPoint(секунда, количество) for секунда, количество in последние),
            maxlen=120,
        )

    def _обновить(self) -> None:
        if not self._точки:
            self._кривая.setData([], [])
            return
        первая = self._точки[0].секунда
        x = [точка.секунда - первая for точка in self._точки]
        y = [точка.количество for точка in self._точки]
        self._кривая.setData(x, y)
        максимум_y = max(max(y) + 1, 5)
        максимум_x = max(max(x), 60)
        self.график.setYRange(0, максимум_y, padding=0.08)
        self.график.setXRange(0, максимум_x, padding=0)


class ProtocolPieWidget(QWidget):
    """Легкая круговая диаграмма распределения протоколов."""

    цвета = {
        "TCP": "#3fa7ff",
        "UDP": "#f3c969",
        "DNS": "#8bd17c",
        "HTTP": "#ff8f5f",
        "ICMP": "#c58cff",
        "IPv6": "#70d6d0",
        "ARP": "#ffdd57",
        "Ethernet": "#b0bec5",
        "LLC": "#90a4ae",
    }

    def __init__(self, родитель: QWidget | None = None) -> None:
        super().__init__(родитель)
        self._счетчик: Counter[str] = Counter()
        self.setMinimumHeight(220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def добавить_пакет(self, запись: PacketRecord) -> None:
        """Учитывает пакет в распределении протоколов."""

        self._счетчик[запись.протокол] += 1
        self.update()

    def очистить(self) -> None:
        """Очищает диаграмму."""

        self._счетчик.clear()
        self.update()

    def paintEvent(self, _event) -> None:
        художник = QPainter(self)
        художник.setRenderHint(QPainter.RenderHint.Antialiasing)
        область = self.rect().adjusted(12, 12, -12, -12)
        сторона = min(область.width() * 0.55, область.height())
        круг = область.adjusted(0, 0, int(-(область.width() - сторона)), 0)
        круг.setWidth(int(сторона))

        всего = sum(self._счетчик.values())
        if всего == 0:
            художник.setPen(QPen(QColor("#60707d"), 1))
            художник.drawText(область, Qt.AlignmentFlag.AlignCenter, "Диаграмма появится после захвата пакетов")
            return

        старт = 90 * 16
        for протокол, количество in self._счетчик.most_common():
            угол = int(360 * 16 * количество / всего)
            цвет = QColor(self.цвета.get(протокол, "#b0bec5"))
            художник.setBrush(цвет)
            художник.setPen(QPen(QColor("#101418"), 2))
            художник.drawPie(круг, старт, -угол)
            старт -= угол

        x_легенды = круг.right() + 24
        y = область.top() + 8
        художник.setPen(QColor("#e8eef2"))
        художник.drawText(x_легенды, y, "Распределение протоколов")
        y += 24
        for протокол, количество in self._счетчик.most_common(8):
            процент = количество * 100 / всего
            цвет = QColor(self.цвета.get(протокол, "#b0bec5"))
            художник.fillRect(x_легенды, y - 11, 12, 12, цвет)
            художник.setPen(QColor("#cbd7df"))
            художник.drawText(
                x_легенды + 18,
                y,
                f"{протокол}: {количество} ({процент:.1f}%)",
            )
            y += 22


def _цвет_протокола(протокол: str) -> str:
    """Цвет текста строки в зависимости от протокола."""

    return ProtocolPieWidget.цвета.get(протокол, "#e8eef2")
