# Settings Page (Phase 6)
#
# API key entry (masked, saved via keyring - never plaintext), an
# enrichment mode toggle, and a privacy disclosure. "Test Connection"
# buttons make a real, minimal call to each service to confirm the key
# works before saving.

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox, QDialog, QFormLayout, QGroupBox, QLabel, QLineEdit,
    QMessageBox, QPushButton, QVBoxLayout,
)

from vidic.core import secrets

PRIVACY_TEXT = (
    "In Offline / Local-only mode, nothing about this email leaves your machine - "
    "only header parsing, DNS-based SPF/DKIM/DMARC checks (which are always live, "
    "regardless of mode), and local IOC extraction run.\n\n"
    "In Full mode, extracted links, domains, IP addresses, and attachment hashes "
    "are additionally sent to VirusTotal, AbuseIPDB, URLhaus, and RDAP for "
    "reputation lookups. Do not use Full mode when investigating a targeted "
    "attack you don't want to tip off - submitting an attacker's own "
    "infrastructure to a public service can alert them that they've been noticed."
)


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VIDIC Settings")
        self.resize(520, 480)
        self._key_inputs = {}
        self._build_ui()
        self._load_current_values()

    def _build_ui(self):
        root = QVBoxLayout(self)

        mode_group = QGroupBox("Enrichment Mode")
        mode_layout = QVBoxLayout(mode_group)
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Offline / Local-only (no data leaves this machine)", secrets.MODE_OFFLINE)
        self.mode_combo.addItem("Full (query VirusTotal / AbuseIPDB / URLhaus / RDAP)", secrets.MODE_FULL)
        mode_layout.addWidget(self.mode_combo)
        root.addWidget(mode_group)

        keys_group = QGroupBox("API Keys (stored securely via your OS keychain)")
        form = QFormLayout(keys_group)

        for label, key_name in [
            ("VirusTotal API key", "virustotal"),
            ("AbuseIPDB API key", "abuseipdb"),
            ("URLhaus Auth-Key", "urlhaus"),
        ]:
            field = QLineEdit()
            field.setEchoMode(QLineEdit.EchoMode.Password)
            field.setPlaceholderText("(leave blank to keep current key)")
            self._key_inputs[key_name] = field

            test_button = QPushButton("Test")
            test_button.clicked.connect(lambda _, k=key_name, f=field: self._test_key(k, f))

            form.addRow(label, field)
            form.addRow("", test_button)

        note = QLabel("RDAP and DNS-based auth checks (SPF/DKIM/DMARC) never need a key.")
        note.setStyleSheet("color: #666; font-style: italic;")
        form.addRow(note)

        root.addWidget(keys_group)

        privacy_label = QLabel(PRIVACY_TEXT)
        privacy_label.setWordWrap(True)
        privacy_label.setStyleSheet("color: #444; padding: 8px; background: #f5f5f5; border-radius: 6px;")
        root.addWidget(privacy_label)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self._save)
        root.addWidget(self.save_button)

    def _load_current_values(self):
        current_mode = secrets.get_enrichment_mode()
        index = self.mode_combo.findData(current_mode)
        if index >= 0:
            self.mode_combo.setCurrentIndex(index)

        for key_name, field in self._key_inputs.items():
            if secrets.has_key(key_name):
                field.setPlaceholderText("(a key is already saved - leave blank to keep it)")

    def _test_key(self, key_name, field):
        typed_value = field.text().strip()
        value_to_test = typed_value or secrets.get_key(key_name)

        if not value_to_test:
            QMessageBox.warning(self, "No key", "Enter a key first, or save one previously.")
            return

        try:
            ok, message = self._run_test(key_name, value_to_test)
        except Exception as exc:
            ok, message = False, str(exc)

        if ok:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.warning(self, "Test failed", message)

    @staticmethod
    def _run_test(key_name, value):
        if key_name == "virustotal":
            from vidic.core.threat_intel.virustotal import VirusTotalClient
            result = VirusTotalClient(api_key=value).check_url("https://example.com")
        elif key_name == "abuseipdb":
            from vidic.core.threat_intel.abuseipdb import AbuseIPDBClient
            result = AbuseIPDBClient(api_key=value).check_ip("8.8.8.8")
        elif key_name == "urlhaus":
            from vidic.core.threat_intel.urlhaus import URLhausClient
            result = URLhausClient(api_key=value).check_url("https://example.com")
        else:
            return False, f"Unknown key: {key_name}"

        if result.get("checked"):
            return True, f"{key_name} key works."
        return False, result.get("error", "Unknown error - key may be invalid.")

    def _save(self):
        secrets.set_enrichment_mode(self.mode_combo.currentData())

        for key_name, field in self._key_inputs.items():
            value = field.text().strip()
            if value:
                secrets.set_key(key_name, value)

        QMessageBox.information(self, "Saved", "Settings saved.")
        self.accept()