"""Entry point for the VIDIC desktop application."""

import sys

from PySide6.QtWidgets import QApplication

from vidic.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("VIDIC")

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())