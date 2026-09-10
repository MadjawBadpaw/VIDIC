# Settings/Secrets Module (Phase 6)
#
# keyring-backed API key storage - keys never touch a plaintext file
# in the repo. Falls back to a clear "unavailable" state rather than
# crashing if no OS credential backend is present.

from __future__ import annotations

import keyring
import keyring.errors
from PySide6.QtCore import QSettings

SERVICE_NAME = 'VIDIC'
KEY_NAMES = ('virustotal', 'abuseipdb', 'urlhaus')

MODE_FULL = 'full'
MODE_OFFLINE = 'offline'


def get_key(name):
    try:
        return keyring.get_password(SERVICE_NAME, name)
    except keyring.errors.KeyringError:
        return None


def set_key(name, value):
    try:
        keyring.set_password(SERVICE_NAME, name, value)
        return True
    except keyring.errors.KeyringError:
        return False


def delete_key(name):
    try:
        keyring.delete_password(SERVICE_NAME, name)
        return True
    except keyring.errors.KeyringError:
        return False


def has_key(name):
    return bool(get_key(name))


def get_enrichment_mode():
    settings = QSettings('VIDIC', 'VIDIC')
    return settings.value('enrichment_mode', MODE_OFFLINE)


def set_enrichment_mode(mode):
    settings = QSettings('VIDIC', 'VIDIC')
    settings.setValue('enrichment_mode', mode)