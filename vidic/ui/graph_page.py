# Graph View (Phase 7)
#
# Renders the IOC relationship graph built in vidic.core.graph using
# matplotlib embedded in a Qt dialog (FigureCanvasQTAgg) - no browser,
# no JavaScript, no external graph database. Opened either for one
# specific analysis ("show me what's connected to this email") or for
# the whole history at once.

from __future__ import annotations

import networkx as nx
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QPushButton, QSpinBox, QTextEdit, QVBoxLayout,
)

from vidic.core import graph as graph_core

NODE_COLOR_EMAIL_BY_VERDICT = {
    "Safe": "#2e7d32",
    "Suspicious": "#ef6c00",
    "High Risk": "#c62828",
    "Critical Phishing": "#8e0000",
}
NODE_COLOR_EMAIL_DEFAULT = "#616161"
NODE_COLOR_IOC = "#1565c0"

NODE_SIZE_EMAIL = 700
NODE_SIZE_IOC = 350


class GraphViewDialog(QDialog):
    """Shows either the full IOC relationship graph across all saved
    analyses, or the neighborhood around one specific analysis.

    Pass `focus_analysis_id=None` for the full-history view, or an
    analysis id to focus on that email and whatever shares an
    indicator with it.
    """

    def __init__(self, focus_analysis_id: int | None = None, parent=None):
        super().__init__(parent)
        self._focus_analysis_id = focus_analysis_id
        self.setWindowTitle("IOC Relationship Graph")
        self.resize(900, 700)
        self._build_ui()
        self._reload()

    def _build_ui(self):
        root = QVBoxLayout(self)

        controls_row = QHBoxLayout()

        if self._focus_analysis_id is not None:
            controls_row.addWidget(QLabel("Hops from this email:"))
            self.hops_spin = QSpinBox()
            self.hops_spin.setRange(1, 4)
            self.hops_spin.setValue(2)
            self.hops_spin.valueChanged.connect(self._reload)
            controls_row.addWidget(self.hops_spin)

            self.show_all_button = QPushButton("Show Full History Graph")
            self.show_all_button.clicked.connect(self._switch_to_full_graph)
            controls_row.addWidget(self.show_all_button)
        else:
            self.hops_spin = None

        controls_row.addStretch(1)
        self.stats_label = QLabel()
        self.stats_label.setStyleSheet("color: #666;")
        controls_row.addWidget(self.stats_label)
        root.addLayout(controls_row)

        self.figure = Figure(figsize=(8, 6))
        self.canvas = FigureCanvasQTAgg(self.figure)
        root.addWidget(self.canvas, stretch=3)

        clusters_label = QLabel("Emails sharing infrastructure with each other:")
        clusters_label.setStyleSheet("font-weight: bold; margin-top: 6px;")
        root.addWidget(clusters_label)

        self.clusters_view = QTextEdit()
        self.clusters_view.setReadOnly(True)
        self.clusters_view.setMaximumHeight(140)
        root.addWidget(self.clusters_view, stretch=1)

    def _switch_to_full_graph(self):
        self._focus_analysis_id = None
        # Rebuild the controls row without the hops spinner / show-all
        # button, since they no longer apply once viewing everything.
        old_layout = self.layout()
        while old_layout.count():
            item = old_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
        self._build_ui()
        self._reload()

    def _reload(self):
        full_graph = graph_core.build_graph()

        if self._focus_analysis_id is not None:
            hops = self.hops_spin.value() if self.hops_spin else 2
            display_graph = graph_core.get_neighborhood(full_graph, self._focus_analysis_id, hops=hops)
        else:
            display_graph = full_graph

        self._draw_graph(display_graph)
        self._update_stats(display_graph)
        self._update_clusters_text(full_graph)

    def _draw_graph(self, graph: nx.Graph):
        self.figure.clear()
        ax = self.figure.add_subplot(111)

        if graph.number_of_nodes() == 0:
            ax.text(
                0.5, 0.5, "No indicators recorded for this graph yet.\n"
                "Analyses saved before graph tracking was added won't appear here.",
                ha="center", va="center", wrap=True, fontsize=10, color="#666",
            )
            ax.axis("off")
            self.canvas.draw()
            return

        layout = nx.spring_layout(graph, seed=42, k=0.6)

        email_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "email"]
        ioc_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "ioc"]

        email_colors = [
            NODE_COLOR_EMAIL_BY_VERDICT.get(graph.nodes[n].get("verdict"), NODE_COLOR_EMAIL_DEFAULT)
            for n in email_nodes
        ]

        nx.draw_networkx_edges(graph, layout, ax=ax, edge_color="#bbbbbb", width=1)
        nx.draw_networkx_nodes(
            graph, layout, ax=ax, nodelist=ioc_nodes,
            node_color=NODE_COLOR_IOC, node_size=NODE_SIZE_IOC, node_shape="s",
        )
        nx.draw_networkx_nodes(
            graph, layout, ax=ax, nodelist=email_nodes,
            node_color=email_colors, node_size=NODE_SIZE_EMAIL, node_shape="o",
        )

        email_labels = {n: self._truncate(graph.nodes[n].get("subject", "")) for n in email_nodes}
        ioc_labels = {n: self._truncate(graph.nodes[n].get("ioc_value", "")) for n in ioc_nodes}

        nx.draw_networkx_labels(graph, layout, labels=email_labels, ax=ax, font_size=7)
        nx.draw_networkx_labels(graph, layout, labels=ioc_labels, ax=ax, font_size=6, font_color="#333333")

        ax.axis("off")
        self.figure.tight_layout()
        self.canvas.draw()

    def _update_stats(self, displayed_graph: nx.Graph):
        stats = graph_core.get_stats(displayed_graph)
        self.stats_label.setText(
            f"{stats.email_count} emails · {stats.ioc_count} indicators · "
            f"{stats.shared_ioc_count} shared"
        )

    def _update_clusters_text(self, full_graph: nx.Graph):
        clusters = graph_core.find_shared_ioc_clusters(full_graph)
        if not clusters:
            self.clusters_view.setPlainText(
                "No analyzed emails currently share any indicator with each other."
            )
            return

        lines = []
        for cluster in clusters:
            subjects = ", ".join(e["subject"] for e in cluster["emails"])
            shared_values = ", ".join(
                f"{ioc['ioc_type']}:{ioc['ioc_value']}" for ioc in cluster["shared_iocs"]
            )
            lines.append(f"[{cluster['size']} emails] {subjects}")
            lines.append(f"    shared: {shared_values}")
            lines.append("")

        self.clusters_view.setPlainText("\n".join(lines))

    @staticmethod
    def _truncate(text: str, limit: int = 28) -> str:
        text = text or ""
        return text if len(text) <= limit else text[: limit - 1] + "…"