from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QTextEdit, QVBoxLayout, QWidget,
)

from vidic.core.parser import EmailParseError, EmailParser
from vidic.core.auth import AuthEngine
from vidic.core.ioc import IOCExtractor
from vidic.core.risk import RiskEngine
from vidic.core.report_formatter import format_report
from vidic.core.threat_intel_runner import gather_threat_intel
from vidic.core import secrets
from vidic.core import db
from vidic.ui.drop_area import DropArea
from vidic.ui.settings_page import SettingsDialog
from vidic.ui.history_page import HistoryDialog


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("VIDIC - Email Threat Intelligence & Detection Center")
        self.resize(900, 650)
        self._parser = EmailParser()
        self._auth_engine = AuthEngine()
        self._ioc_extractor = IOCExtractor()
        self._risk_engine = RiskEngine()
        self._selected_path: Path | None = None
        self._last_result: dict | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        self.drop_area = DropArea(on_file_dropped=self._set_selected_file)
        root.addWidget(self.drop_area)

        button_row = QHBoxLayout()
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self._browse_for_file)
        button_row.addWidget(self.browse_button)

        self.selected_label = QLabel("No file selected")
        self.selected_label.setStyleSheet("color: #666;")
        button_row.addWidget(self.selected_label, stretch=1)

        self.settings_button = QPushButton("Settings")
        self.settings_button.clicked.connect(self._open_settings)
        button_row.addWidget(self.settings_button)

        self.history_button = QPushButton("History")
        self.history_button.clicked.connect(self._open_history)
        button_row.addWidget(self.history_button)

        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.setEnabled(False)
        self.analyze_button.clicked.connect(self._run_analysis)
        button_row.addWidget(self.analyze_button)

        self.save_button = QPushButton("Save to History")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self._save_to_history)
        button_row.addWidget(self.save_button)
        root.addLayout(button_row)

        self.mode_label = QLabel()
        self.mode_label.setStyleSheet("color: #666; font-style: italic;")
        root.addWidget(self.mode_label)
        self._refresh_mode_label()

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        root.addWidget(self.progress_bar)

        report_label = QLabel("Investigation Report")
        report_label.setStyleSheet("font-weight: bold; margin-top: 8px;")
        root.addWidget(report_label)

        self.report_view = QTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setPlaceholderText("Parsed email details will appear here after analysis.")
        root.addWidget(self.report_view, stretch=1)

    def _refresh_mode_label(self) -> None:
        mode = secrets.get_enrichment_mode()
        text = "Mode: Full (queries VirusTotal / AbuseIPDB / URLhaus / RDAP)" \
            if mode == secrets.MODE_FULL else "Mode: Offline / Local-only (no data leaves this machine, aside from live DNS auth checks)"
        self.mode_label.setText(text)

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self)
        dialog.exec()
        self._refresh_mode_label()

    def _open_history(self) -> None:
        dialog = HistoryDialog(self)
        dialog.exec()

    def _save_to_history(self) -> None:
        if self._last_result is None:
            return
        r = self._last_result
        db.save_analysis(
            subject=r['subject'],
            sender=r['sender'],
            verdict=r['verdict'],
            risk_score=r['risk_score'],
            analysis_data={
                'report_text': r['report_text'],
                'fired_rules': r['fired_rules'],
                'iocs': r['iocs'],
            },
        )
        QMessageBox.information(self, "Saved", "This investigation was saved to History.")

    def _browse_for_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select .eml file", "", "Email files (*.eml)")
        if file_path:
            self._set_selected_file(Path(file_path))

    def _set_selected_file(self, path: Path) -> None:
        self._selected_path = path
        self.selected_label.setText(str(path.name))
        self.analyze_button.setEnabled(True)
        self.report_view.clear()

    def _run_analysis(self) -> None:
        if self._selected_path is None:
            return
        self.progress_bar.setRange(0, 0)
        try:
            parsed = self._parser.parse_file(self._selected_path)
            auth = self._auth_engine.verify(parsed)
            iocs = self._ioc_extractor.extract(parsed)

            threat_intel_hits = None
            threat_intel_by_service = {}
            if secrets.get_enrichment_mode() == secrets.MODE_FULL:
                threat_intel_hits, threat_intel_by_service = gather_threat_intel(iocs)

            risk = self._risk_engine.assess(parsed, auth, threat_intel_hits=threat_intel_hits)
        except EmailParseError as exc:
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(0)
            QMessageBox.critical(self, "Parse failed", str(exc))
            return

        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        report_text = format_report(parsed, auth, iocs, risk, threat_intel_by_service)
        self.report_view.setPlainText(report_text)

        self._last_result = {
            'subject': parsed.subject,
            'sender': parsed.sender,
            'verdict': risk.verdict,
            'risk_score': risk.score,
            'report_text': report_text,
            'fired_rules': [{'name': r.name, 'weight': r.weight, 'detail': r.detail} for r in risk.fired_rules],
            'iocs': [{'type': i.type, 'value': i.value, 'source': i.source} for i in iocs],
        }
        self.save_button.setEnabled(True)