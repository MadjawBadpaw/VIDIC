# History Page (Phase 4)

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QLineEdit, QMessageBox, QPushButton, QSpinBox, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout,
)

from vidic.core import db
from vidic.ui.graph_page import GraphViewDialog

COLUMNS = ["Name", "Sender", "Verdict", "Date"]


class ReportViewerDialog(QDialog):
    def __init__(self, report_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Saved Investigation Report")
        self.resize(700, 600)
        layout = QVBoxLayout(self)
        view = QTextEdit()
        view.setReadOnly(True)
        view.setHtml(report_text)
        layout.addWidget(view)


class HistoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Investigation History")
        self.resize(750, 500)
        self._rows = []
        self._build_ui()
        self._reload()

    def _build_ui(self):
        root = QVBoxLayout(self)

        search_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by name, subject, sender, or verdict...")
        self.search_input.textChanged.connect(self._reload)
        search_row.addWidget(self.search_input)
        root.addLayout(search_row)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.cellDoubleClicked.connect(self._open_selected_report)
        self.table.itemSelectionChanged.connect(self._update_button_states)
        root.addWidget(self.table)

        self.selection_label = QLabel("No entries selected")
        self.selection_label.setStyleSheet("color: #666;")
        root.addWidget(self.selection_label)

        action_row = QHBoxLayout()
        self.rename_button = QPushButton("Rename Selected")
        self.rename_button.clicked.connect(self._rename_selected)
        action_row.addWidget(self.rename_button)

        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.setStyleSheet("QPushButton { color: #c62828; }")
        self.delete_button.clicked.connect(self._delete_selected)
        action_row.addWidget(self.delete_button)

        self.graph_button = QPushButton("View Graph")
        self.graph_button.clicked.connect(self._view_graph)
        action_row.addWidget(self.graph_button)

        action_row.addStretch(1)
        root.addLayout(action_row)

        purge_row = QHBoxLayout()
        purge_row.addWidget(QLabel("Delete entries older than"))
        self.purge_days = QSpinBox()
        self.purge_days.setRange(1, 3650)
        self.purge_days.setValue(90)
        purge_row.addWidget(self.purge_days)
        purge_row.addWidget(QLabel("days"))
        purge_button = QPushButton("Purge")
        purge_button.clicked.connect(self._purge_old)
        purge_row.addWidget(purge_button)
        purge_row.addStretch(1)
        root.addLayout(purge_row)

        self._update_button_states()

    def _reload(self):
        query = self.search_input.text().strip()
        self._rows = db.search_analyses(query) if query else db.get_all_analyses()

        self.table.setRowCount(len(self._rows))
        for i, row in enumerate(self._rows):
            display_name = row.get("label") or row["subject"]
            self.table.setItem(i, 0, QTableWidgetItem(display_name))
            self.table.setItem(i, 1, QTableWidgetItem(row["sender"]))
            self.table.setItem(i, 2, QTableWidgetItem(f"{row['verdict']} ({row['risk_score']})"))
            self.table.setItem(i, 3, QTableWidgetItem(row["created_at"][:19].replace("T", " ")))

        self._update_button_states()

    def _selected_row_indices(self) -> list[int]:
        seen = set()
        indices = []
        for index in self.table.selectionModel().selectedRows():
            if index.row() not in seen:
                seen.add(index.row())
                indices.append(index.row())
        return sorted(indices)

    def _update_button_states(self):
        count = len(self._selected_row_indices())
        if count == 0:
            self.selection_label.setText("No entries selected")
        elif count == 1:
            self.selection_label.setText("1 entry selected")
        else:
            self.selection_label.setText(f"{count} entries selected")

        self.rename_button.setEnabled(count == 1)
        self.delete_button.setEnabled(count >= 1)

    def _rename_selected(self):
        row_indices = self._selected_row_indices()
        if len(row_indices) != 1:
            QMessageBox.information(self, "Select one entry", "Select exactly one entry to rename.")
            return

        row = self._rows[row_indices[0]]
        current_name = row.get("label") or row["subject"]
        new_name, ok = QInputDialog.getText(self, "Rename entry", "New name:", text=current_name)
        if ok and new_name.strip():
            db.rename_analysis(row["id"], new_name.strip())
            self._reload()

    def _delete_selected(self):
        row_indices = self._selected_row_indices()
        if not row_indices:
            return

        selected_rows = [self._rows[i] for i in row_indices]
        names = [r.get("label") or r["subject"] for r in selected_rows]

        if len(names) == 1:
            message = f'Delete "{names[0]}"? This cannot be undone.'
        else:
            preview = "\n".join(f"- {n}" for n in names[:5])
            if len(names) > 5:
                preview += f"\n... and {len(names) - 5} more"
            message = f"Delete {len(names)} entries? This cannot be undone.\n\n{preview}"

        confirm = QMessageBox.question(
            self, "Confirm delete", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        for row in selected_rows:
            db.delete_analysis(row["id"])

        self._reload()

    def _view_graph(self):
        row_indices = self._selected_row_indices()

        if len(row_indices) == 1:
            analysis_id = self._rows[row_indices[0]]["id"]
            dialog = GraphViewDialog(focus_analysis_id=analysis_id, parent=self)
        else:
            # No selection, or multiple selected: show the full history
            # graph rather than guessing which one to focus on.
            dialog = GraphViewDialog(focus_analysis_id=None, parent=self)

        dialog.exec()

    def _open_selected_report(self, row_index, _column):
        if row_index >= len(self._rows):
            return
        analysis_id = self._rows[row_index]["id"]
        full = db.get_analysis_by_id(analysis_id)
        if full is None:
            QMessageBox.warning(self, "Not found", "This entry no longer exists.")
            self._reload()
            return

        report_text = full["analysis_json"].get("report_text", "(no report text saved)")
        viewer = ReportViewerDialog(report_text, self)
        viewer.exec()

    def _purge_old(self):
        days = self.purge_days.value()
        confirm = QMessageBox.question(
            self, "Confirm purge",
            f"Delete all history entries older than {days} days? This cannot be undone.",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        deleted = db.delete_analyses_older_than(days)
        QMessageBox.information(self, "Purged", f"Deleted {deleted} entr{'y' if deleted == 1 else 'ies'}.")
        self._reload()