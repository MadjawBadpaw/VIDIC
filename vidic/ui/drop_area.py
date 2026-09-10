# Drop Area widget (extracted from main_window)

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QFrame, QLabel, QMessageBox, QVBoxLayout


class DropArea(QFrame):
    def __init__(self, on_file_dropped):
        super().__init__()
        self._on_file_dropped = on_file_dropped
        self.setAcceptDrops(True)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(140)
        self.setStyleSheet("QFrame { border: 2px dashed #888; border-radius: 8px; }")
        layout = QVBoxLayout(self)
        self.label = QLabel("Drag & drop a .eml file here")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if not urls:
            return
        path = Path(urls[0].toLocalFile())
        if path.suffix.lower() != ".eml":
            QMessageBox.warning(self, "Unsupported file", "Please drop a .eml file.")
            return
        self._on_file_dropped(path)