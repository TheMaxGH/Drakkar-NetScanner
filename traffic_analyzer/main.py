"""Точка входа приложения DRAKKAR NetScanner."""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from traffic_analyzer.gui.main_window import MainWindow


def main() -> int:
    """Создает Qt-приложение и запускает главный цикл событий."""

    приложение = QApplication(sys.argv)
    приложение.setApplicationName("DRAKKAR NetScanner")
    приложение.setOrganizationName("DRAKKAR")

    окно = MainWindow()
    окно.show()

    return приложение.exec()


if __name__ == "__main__":
    raise SystemExit(main())
