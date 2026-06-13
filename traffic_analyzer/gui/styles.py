"""QSS-стили приложения DRAKKAR NetScanner."""

ТЕМНАЯ_ТЕМА = """
QMainWindow, QWidget {
    background-color: #101418;
    color: #e8eef2;
    font-family: "Segoe UI", "Arial";
    font-size: 10pt;
}

QFrame#верхняяПанель, QFrame#карточкаСтатистики {
    background-color: #171d23;
    border: 1px solid #2a3440;
    border-radius: 8px;
}

QLabel#заголовок {
    font-size: 18pt;
    font-weight: 700;
    color: #ffffff;
}

QLabel#подпись, QLabel#статистика {
    color: #9fb0bd;
}

QComboBox, QLineEdit {
    background-color: #0d1116;
    border: 1px solid #334150;
    border-radius: 6px;
    padding: 7px 9px;
    color: #e8eef2;
    min-height: 18px;
}

QComboBox:hover, QLineEdit:hover {
    border-color: #4b6b88;
}

QComboBox:focus, QLineEdit:focus {
    border-color: #3fa7ff;
}

QPushButton {
    background-color: #24313c;
    border: 1px solid #354656;
    border-radius: 6px;
    color: #edf5fa;
    padding: 7px 12px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #2c3b48;
    border-color: #4d6478;
}

QPushButton:pressed {
    background-color: #1c2630;
}

QPushButton:disabled {
    background-color: #182027;
    color: #60707d;
    border-color: #26313a;
}

QPushButton#старт {
    background-color: #12715e;
    border-color: #19967d;
}

QPushButton#стоп {
    background-color: #8e2d38;
    border-color: #b94350;
}

QTableView, QTreeWidget {
    background-color: #0d1116;
    alternate-background-color: #121922;
    border: 1px solid #28333d;
    border-radius: 8px;
    gridline-color: #24303a;
    selection-background-color: #214f75;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #18212a;
    color: #cbd7df;
    border: 0;
    border-right: 1px solid #2b3742;
    padding: 8px;
    font-weight: 700;
}

QScrollBar:vertical, QScrollBar:horizontal {
    background: #0d1116;
    width: 12px;
    height: 12px;
}

QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: #354656;
    border-radius: 6px;
}

QScrollBar::add-line, QScrollBar::sub-line {
    width: 0;
    height: 0;
}

QSplitter::handle {
    background-color: #26313a;
}

QStatusBar {
    background-color: #0d1116;
    color: #a9b8c4;
}
"""
