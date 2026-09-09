"""Modern, local-only desktop dashboard for the ELLIOT defence engine.

The view deliberately has no privileged imports and no network client. Every
number, chart, and event shown here is projected from the local daemon's
official IPC response. Visual animations only interpolate already received
values; they never create synthetic threat telemetry.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

from .presentation import (
    dashboard_projection,
    format_event,
    format_indicator,
    quarantine_label,
    scan_projection,
)

try:
    import customtkinter as ctk
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    from tkinter import filedialog, messagebox
except ImportError as exc:  # Import remains safe on server/headless installs.
    ctk = None
    Figure = None
    FigureCanvasTkAgg = None
    filedialog = None
    messagebox = None
    GUI_IMPORT_ERROR: ImportError | None = exc
else:
    GUI_IMPORT_ERROR = None


logger = logging.getLogger("elliot.gui.view")
_BaseView = ctk.CTk if ctk is not None else object


class ElliotView(_BaseView):
    """Professional security dashboard backed exclusively by local IPC data."""

    COLORS = {
        "canvas": "#070B14",
        "surface": "#0D1422",
        "surface_alt": "#101B2D",
        "border": "#1B2C43",
        "ink": "#ECF7FF",
        "muted": "#91A5BB",
        "cyan": "#22D3EE",
        "cyan_dim": "#0E7490",
        "emerald": "#34D399",
        "amber": "#FBBF24",
        "rose": "#FB7185",
        "violet": "#A78BFA",
    }

    def __init__(self, *, banner_text: str | None = None) -> None:
        if ctk is None:
            raise RuntimeError(
                "GUI dependencies are unavailable; install customtkinter, matplotlib and Tkinter"
            ) from GUI_IMPORT_ERROR
        super().__init__()
        self._banner_text = banner_text
        self._quarantine_ids_by_label: dict[str, str] = {}
        self._closing_callback: Callable[[], None] | None = None
        self._risk_value = 0.0
        self._risk_target = 0.0
        self._risk_animation_job: Any | None = None
        self._busy_animation_job: Any | None = None
        self._busy_tick = 0

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.title("ELLIOT — Local Zero-Day Defence")
        self.configure(fg_color=self.COLORS["canvas"])
        self.minsize(1100, 720)
        self._load_geometry()
        self.protocol("WM_DELETE_WINDOW", self._request_close)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_dashboard()

    # Layout -----------------------------------------------------------------
    def _build_sidebar(self) -> None:
        self.sidebar = ctk.CTkFrame(
            self,
            width=250,
            corner_radius=0,
            fg_color=self.COLORS["surface"],
            border_width=0,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)
        self.sidebar.grid_rowconfigure(12, weight=1)

        ctk.CTkLabel(
            self.sidebar,
            text="◈  ELLIOT",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=self.COLORS["cyan"],
        ).grid(row=0, column=0, padx=23, pady=(30, 0), sticky="w")
        ctk.CTkLabel(
            self.sidebar,
            text="LOCAL ZERO-DAY DEFENCE",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=self.COLORS["muted"],
        ).grid(row=1, column=0, padx=25, pady=(0, 22), sticky="w")

        self.status_pill = ctk.CTkLabel(
            self.sidebar,
            text="  ●  CONNECTING TO LOCAL ENGINE  ",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=self.COLORS["amber"],
            fg_color="#342A12",
            corner_radius=14,
            height=30,
        )
        self.status_pill.grid(row=2, column=0, padx=20, pady=(0, 18), sticky="ew")

        self._section_label("LOCAL SENSORS", 3)
        self.component_label = ctk.CTkLabel(
            self.sidebar,
            text="local sensors  •  checking",
            justify="left",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=self.COLORS["muted"],
        )
        self.component_label.grid(row=4, column=0, padx=25, pady=(0, 12), sticky="ew")
        self.policy_label = ctk.CTkLabel(
            self.sidebar,
            text="POLICY  ·  UNKNOWN",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=self.COLORS["violet"],
        )
        self.policy_label.grid(row=5, column=0, padx=25, pady=(0, 22), sticky="ew")

        self._section_label("OPERATIONS", 6)
        self.refresh_button = ctk.CTkButton(
            self.sidebar,
            text="↻   Refresh telemetry",
            anchor="w",
            height=42,
            corner_radius=10,
            fg_color=self.COLORS["surface_alt"],
            hover_color=self.COLORS["border"],
            text_color=self.COLORS["ink"],
        )
        self.refresh_button.grid(row=7, column=0, padx=18, pady=4, sticky="ew")
        self.scan_button = ctk.CTkButton(
            self.sidebar,
            text="⌁   Analyse a file",
            anchor="w",
            height=42,
            corner_radius=10,
            fg_color=self.COLORS["cyan_dim"],
            hover_color="#155E75",
            text_color=self.COLORS["ink"],
        )
        self.scan_button.grid(row=8, column=0, padx=18, pady=4, sticky="ew")
        self.quarantine_button = ctk.CTkButton(
            self.sidebar,
            text="▣   Review quarantine",
            anchor="w",
            height=42,
            corner_radius=10,
            fg_color=self.COLORS["surface_alt"],
            hover_color=self.COLORS["border"],
            text_color=self.COLORS["ink"],
        )
        self.quarantine_button.grid(row=9, column=0, padx=18, pady=4, sticky="ew")

        if self._banner_text:
            self.demo_banner = ctk.CTkLabel(
                self.sidebar,
                text=self._banner_text,
                wraplength=200,
                justify="left",
                text_color=self.COLORS["amber"],
                fg_color="#302711",
                corner_radius=8,
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            )
            self.demo_banner.grid(row=11, column=0, padx=18, pady=(14, 8), sticky="ew")

        self.busy_label = ctk.CTkLabel(
            self.sidebar,
            text="LOCAL-ONLY · NO CLOUD TELEMETRY",
            wraplength=205,
            justify="left",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=self.COLORS["muted"],
        )
        self.busy_label.grid(row=13, column=0, padx=22, pady=(12, 28), sticky="sw")

    def _section_label(self, text: str, row: int) -> None:
        ctk.CTkLabel(
            self.sidebar,
            text=text,
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color="#5E748D",
        ).grid(row=row, column=0, padx=25, pady=(0, 8), sticky="ew")

    def _build_dashboard(self) -> None:
        self.main = ctk.CTkFrame(self, fg_color=self.COLORS["canvas"], corner_radius=0)
        self.main.grid(row=0, column=1, padx=0, pady=0, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(4, weight=1)

        header = ctk.CTkFrame(self.main, fg_color="transparent")
        header.grid(row=0, column=0, padx=30, pady=(26, 14), sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Security command center",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=self.COLORS["ink"],
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="LIVE LOCAL TELEMETRY",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=self.COLORS["emerald"],
            fg_color="#102C28",
            corner_radius=12,
            height=27,
        ).grid(row=0, column=1, padx=(15, 0), sticky="e")
        self.header_subtitle = ctk.CTkLabel(
            header,
            text="Entropy analysis and endpoint events are displayed only when supplied by the local engine.",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=self.COLORS["muted"],
        )
        self.header_subtitle.grid(row=1, column=0, columnspan=2, pady=(3, 0), sticky="w")

        metrics = ctk.CTkFrame(self.main, fg_color="transparent")
        metrics.grid(row=1, column=0, padx=30, pady=(0, 18), sticky="ew")
        for column in range(4):
            metrics.grid_columnconfigure(column, weight=1)
        self.protection_metric = self._metric_card(metrics, 0, "ENGINE STATUS", "Checking", self.COLORS["amber"])
        self.event_metric = self._metric_card(metrics, 1, "EVENTS OBSERVED", "0", self.COLORS["cyan"])
        self.threat_metric = self._metric_card(metrics, 2, "HIGH-RISK SIGNALS", "0", self.COLORS["rose"])
        self.quarantine_metric = self._metric_card(metrics, 3, "QUARANTINE ITEMS", "0", self.COLORS["violet"])

        command = ctk.CTkFrame(
            self.main,
            fg_color=self.COLORS["surface"],
            corner_radius=14,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        command.grid(row=2, column=0, padx=30, pady=(0, 18), sticky="ew")
        command.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            command,
            text="RISK SIGNAL",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=self.COLORS["muted"],
        ).grid(row=0, column=0, padx=(18, 10), pady=(14, 0), sticky="w")
        self.risk_number_label = ctk.CTkLabel(
            command,
            text="0 / 100",
            font=ctk.CTkFont(family="Segoe UI", size=25, weight="bold"),
            text_color=self.COLORS["emerald"],
        )
        self.risk_number_label.grid(row=1, column=0, padx=(18, 12), pady=(0, 14), sticky="w")
        self.risk_progress = ctk.CTkProgressBar(
            command,
            height=12,
            corner_radius=8,
            fg_color="#172538",
            progress_color=self.COLORS["emerald"],
        )
        self.risk_progress.grid(row=1, column=1, padx=(0, 18), pady=(0, 14), sticky="ew")
        self.risk_progress.set(0)
        self.risk_context_label = ctk.CTkLabel(
            command,
            text="No file analysis is selected.",
            anchor="w",
            justify="left",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=self.COLORS["muted"],
        )
        self.risk_context_label.grid(row=2, column=0, columnspan=2, padx=18, pady=(0, 14), sticky="ew")

        charts = ctk.CTkFrame(self.main, fg_color="transparent")
        charts.grid(row=3, column=0, padx=30, pady=(0, 18), sticky="nsew")
        charts.grid_columnconfigure(0, weight=3)
        charts.grid_columnconfigure(1, weight=2)
        self._build_entropy_chart(charts)
        self._build_telemetry_chart(charts)

        self.tabs = ctk.CTkTabview(
            self.main,
            fg_color=self.COLORS["surface"],
            segmented_button_fg_color="#172538",
            segmented_button_selected_color=self.COLORS["cyan_dim"],
            segmented_button_selected_hover_color="#155E75",
            segmented_button_unselected_color="#172538",
            segmented_button_unselected_hover_color=self.COLORS["border"],
            text_color=self.COLORS["ink"],
        )
        self.tabs.grid(row=4, column=0, padx=30, pady=(0, 28), sticky="nsew")
        for name in ("Analysis", "Event Stream", "Quarantine"):
            self.tabs.add(name)
        self._build_analysis_tab()
        self._build_events_tab()
        self._build_quarantine_tab()

    def _metric_card(self, parent: Any, column: int, label: str, value: str, accent: str) -> dict[str, Any]:
        card = ctk.CTkFrame(
            parent,
            fg_color=self.COLORS["surface"],
            border_width=1,
            border_color=self.COLORS["border"],
            corner_radius=14,
        )
        card.grid(row=0, column=column, padx=5, sticky="ew")
        ctk.CTkLabel(
            card,
            text=label,
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=self.COLORS["muted"],
        ).pack(fill="x", padx=16, pady=(13, 0))
        value_label = ctk.CTkLabel(
            card,
            text=value,
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
            text_color=accent,
        )
        value_label.pack(fill="x", padx=16, pady=(0, 3))
        detail = ctk.CTkLabel(
            card,
            text="local daemon source",
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#66819B",
        )
        detail.pack(fill="x", padx=16, pady=(0, 12))
        return {"value": value_label, "detail": detail, "accent": accent}

    def _build_entropy_chart(self, parent: Any) -> None:
        card = self._chart_card(parent, 0, "ENTROPY PROFILE", "Block-level Shannon entropy")
        self.entropy_figure = Figure(figsize=(6.4, 2.5), dpi=100, facecolor=self.COLORS["surface"])
        self.entropy_axes = self.entropy_figure.add_subplot(111)
        self._style_axes(self.entropy_axes)
        self.entropy_canvas = FigureCanvasTkAgg(self.entropy_figure, master=card)
        self.entropy_canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._draw_entropy([], [])

    def _build_telemetry_chart(self, parent: Any) -> None:
        card = self._chart_card(parent, 1, "EVENT DISTRIBUTION", "Events in the current local view")
        self.telemetry_figure = Figure(figsize=(4.2, 2.5), dpi=100, facecolor=self.COLORS["surface"])
        self.telemetry_axes = self.telemetry_figure.add_subplot(111)
        self._style_axes(self.telemetry_axes)
        self.telemetry_canvas = FigureCanvasTkAgg(self.telemetry_figure, master=card)
        self.telemetry_canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._draw_telemetry({}, {"low": 0, "elevated": 0, "high": 0})

    def _chart_card(self, parent: Any, column: int, title: str, subtitle: str) -> Any:
        card = ctk.CTkFrame(
            parent,
            fg_color=self.COLORS["surface"],
            border_width=1,
            border_color=self.COLORS["border"],
            corner_radius=14,
        )
        card.grid(row=0, column=column, padx=(0, 9) if column == 0 else (9, 0), sticky="nsew")
        ctk.CTkLabel(
            card,
            text=title,
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=self.COLORS["cyan"],
        ).pack(fill="x", padx=16, pady=(13, 0))
        ctk.CTkLabel(
            card,
            text=subtitle,
            anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=self.COLORS["muted"],
        ).pack(fill="x", padx=16, pady=(0, 3))
        return card

    def _build_analysis_tab(self) -> None:
        tab = self.tabs.tab("Analysis")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.analysis_text = ctk.CTkTextbox(
            tab,
            fg_color="#09111D",
            border_width=1,
            border_color=self.COLORS["border"],
            text_color="#D9EAF7",
            font=ctk.CTkFont(family="Cascadia Mono", size=12),
        )
        self.analysis_text.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")
        self._replace_text(
            self.analysis_text,
            "Select ‘Analyse a file’ to inspect entropy, file structure and explainable scoring evidence.\n",
        )

    def _build_events_tab(self) -> None:
        tab = self.tabs.tab("Event Stream")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.events_text = ctk.CTkTextbox(
            tab,
            fg_color="#09111D",
            border_width=1,
            border_color=self.COLORS["border"],
            text_color="#D9EAF7",
            font=ctk.CTkFont(family="Cascadia Mono", size=12),
        )
        self.events_text.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")
        self._replace_text(self.events_text, "No local daemon events are available.\n")

    def _build_quarantine_tab(self) -> None:
        tab = self.tabs.tab("Quarantine")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        self.quarantine_selector = ctk.CTkOptionMenu(
            tab,
            values=["No quarantine records"],
            fg_color="#172538",
            button_color=self.COLORS["cyan_dim"],
            button_hover_color="#155E75",
        )
        self.quarantine_selector.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="ew")
        self.quarantine_text = ctk.CTkTextbox(
            tab,
            fg_color="#09111D",
            border_width=1,
            border_color=self.COLORS["border"],
            text_color="#D9EAF7",
            font=ctk.CTkFont(family="Cascadia Mono", size=12),
        )
        self.quarantine_text.grid(row=1, column=0, padx=12, pady=6, sticky="nsew")
        self.restore_button = ctk.CTkButton(
            tab,
            text="Restore selected item safely",
            height=38,
            fg_color=self.COLORS["cyan_dim"],
            hover_color="#155E75",
        )
        self.restore_button.grid(row=2, column=0, padx=12, pady=(6, 12), sticky="e")

    # Controller boundary -----------------------------------------------------
    def bind_actions(
        self,
        *,
        on_refresh: Callable[[], None],
        on_scan: Callable[[str], None],
        on_refresh_quarantine: Callable[[], None],
        on_restore: Callable[[str], None],
        on_close: Callable[[], None],
    ) -> None:
        self._closing_callback = on_close
        self.refresh_button.configure(command=on_refresh)
        self.quarantine_button.configure(command=on_refresh_quarantine)
        self.scan_button.configure(command=lambda: self._choose_scan(on_scan))
        self.restore_button.configure(command=lambda: self._request_restore(on_restore))

    def _choose_scan(self, callback: Callable[[str], None]) -> None:
        selected = filedialog.askopenfilename(title="Select a file for ELLIOT analysis")
        if selected:
            callback(selected)

    def _request_restore(self, callback: Callable[[str], None]) -> None:
        label = self.quarantine_selector.get()
        quarantine_id = self._quarantine_ids_by_label.get(label, "")
        if not quarantine_id:
            self.show_error("Restore unavailable", "Select a quarantine record first.")
            return
        confirmed = messagebox.askyesno(
            "Authorised restore",
            "Restore the selected record to its original path? Existing files are never overwritten.",
        )
        if confirmed:
            callback(quarantine_id)

    # Rendering ---------------------------------------------------------------
    def render_dashboard(self, snapshot: dict[str, Any]) -> None:
        projection = dashboard_projection(snapshot)
        state = projection["service_state"]
        state_color = {
            "CONNECTED": self.COLORS["emerald"],
            "DEGRADED": self.COLORS["amber"],
            "DISCONNECTED": self.COLORS["rose"],
        }[state]
        state_background = {
            "CONNECTED": "#102C28",
            "DEGRADED": "#342A12",
            "DISCONNECTED": "#351924",
        }[state]
        self.status_pill.configure(
            text=f"  ●  {state} LOCAL ENGINE  ", text_color=state_color, fg_color=state_background
        )
        components = projection["component_states"]
        if projection["platform"] == "WINDOWS":
            monitor_state = "active" if components["windows_monitor"] else "unavailable"
            component_lines = [
                f"{projection['monitor_kind']}  •  {monitor_state}",
                "execution blocking  •  signed minifilter required",
            ]
        else:
            component_lines = [
                f"fanotify  •  {'active' if components['fanotify'] else 'unavailable'}",
                f"eBPF  •  {'active' if components['ebpf'] else 'unavailable'}",
            ]
        self.component_label.configure(text="\n".join(component_lines))
        self.policy_label.configure(text=f"POLICY  ·  {projection['policy_mode']}")

        telemetry = projection["telemetry"]
        degraded = projection["degraded_components"]
        protection_detail = (
            "all reported sensors ready" if state == "CONNECTED" else
            ("degraded: " + ", ".join(degraded[:2]) if degraded else "local IPC unavailable")
        )
        self._set_metric(self.protection_metric, state, protection_detail, state_color)
        self._set_metric(
            self.event_metric,
            str(telemetry["event_count"]),
            f"{telemetry['scored_event_count']} with a reported score",
            self.COLORS["cyan"],
        )
        self._set_metric(
            self.threat_metric,
            str(telemetry["high_risk_count"]),
            "score ≥ 70 in current event view",
            self.COLORS["rose"],
        )
        self._set_metric(
            self.quarantine_metric,
            str(len(projection["quarantine"])),
            "records reported by local engine",
            self.COLORS["violet"],
        )
        self._draw_telemetry(telemetry["source_counts"], telemetry["risk_bands"])

        event_lines = [format_event(event) for event in projection["events"]]
        self._replace_text(
            self.events_text,
            "\n".join(event_lines) + ("\n" if event_lines else "No local daemon events are available.\n"),
        )
        self._render_quarantine(projection["quarantine"])
        errors = projection["errors"]
        if errors:
            self.header_subtitle.configure(
                text=f"Local dashboard has {len(errors)} unavailable data section(s); displayed values remain explicit."
            )
        elif state == "CONNECTED":
            self.header_subtitle.configure(
                text="Local engine connected. The dashboard does not send telemetry to a cloud service."
            )
        else:
            self.header_subtitle.configure(
                text="Waiting for the local engine. No protection state is inferred while it is disconnected."
            )

    def render_scan_result(self, result: dict[str, Any]) -> None:
        view = scan_projection(result)
        score = max(0, min(100, int(view["pre_execution_score"])))
        self._animate_risk_to(score)
        runtime = view["runtime_score"]
        runtime_text = "not reported" if runtime is None else f"{runtime}/100"
        whole_entropy = view["whole_file_entropy"]
        entropy_text = "not reported" if whole_entropy is None else f"{whole_entropy} bits/byte"
        self.risk_context_label.configure(
            text=(
                f"{Path(view['filepath']).name or 'Selected file'}  ·  {view['decision']}  ·  "
                f"Runtime score: {runtime_text}  ·  Whole-file entropy: {entropy_text}"
            )
        )
        self._draw_entropy(view["block_indices"], view["block_entropies"])

        lines = [
            "ELLIOT LOCAL ANALYSIS RESULT",
            "═" * 48,
            f"Path: {view['filepath']}",
            f"Status: {view['status']}",
            f"Decision: {view['decision']}",
            f"MIME: {view['mime_type']} ({view['mime_extension_consistency']})",
            f"ELF: {view['is_elf']}  |  Duration: {view['duration_ms']:.3f} ms",
            "",
            "EXPLAINABLE INDICATORS",
        ]
        indicators = view["indicators"]
        lines.extend(format_indicator(item) for item in indicators)
        if not indicators:
            lines.append("No scoring indicators were reported.")
        if view["warnings"]:
            lines.extend(["", "WARNINGS"])
            lines.extend(str(item) for item in view["warnings"])
        if view["errors"]:
            lines.extend(["", "ANALYSIS ERRORS"])
            lines.extend(str(item) for item in view["errors"])
        if view["blocks_truncated"]:
            lines.extend(["", "The entropy chart is sampled because the full block list is large."])
        self._replace_text(self.analysis_text, "\n".join(lines) + "\n")
        self.tabs.set("Analysis")

    def _set_metric(self, metric: dict[str, Any], value: str, detail: str, color: str) -> None:
        metric["value"].configure(text=value, text_color=color)
        metric["detail"].configure(text=detail)

    def _render_quarantine(self, items: list[dict[str, Any]]) -> None:
        self._quarantine_ids_by_label.clear()
        labels: list[str] = []
        details: list[str] = []
        for item in items:
            label = quarantine_label(item)
            quarantine_id = str(item.get("quarantine_id", ""))
            if quarantine_id:
                self._quarantine_ids_by_label[label] = quarantine_id
                labels.append(label)
            details.append(json.dumps(item, ensure_ascii=False, indent=2, sort_keys=True))
        if not labels:
            labels = ["No quarantine records"]
        self.quarantine_selector.configure(values=labels)
        self.quarantine_selector.set(labels[0])
        self._replace_text(
            self.quarantine_text,
            "\n\n".join(details) + ("\n" if details else "No quarantine records.\n"),
        )

    def render_restore_result(self, result: dict[str, Any]) -> None:
        restored_path = str(result.get("restored_path", result.get("original_path", "unknown")))
        messagebox.showinfo("Restore completed", f"Restored safely to:\n{restored_path}")

    def show_error(self, title: str, message: str) -> None:
        messagebox.showerror(title, message)

    # Motion / charting -------------------------------------------------------
    def _animate_risk_to(self, target: int) -> None:
        self._risk_target = float(max(0, min(100, target)))
        if self._risk_animation_job is None:
            self._animate_risk_step()

    def _animate_risk_step(self) -> None:
        distance = self._risk_target - self._risk_value
        if abs(distance) < 0.35:
            self._risk_value = self._risk_target
            self._risk_animation_job = None
        else:
            self._risk_value += distance * 0.22
            self._risk_animation_job = self.after(16, self._animate_risk_step)
        value = max(0, min(100, self._risk_value))
        if value >= 70:
            color = self.COLORS["rose"]
        elif value >= 40:
            color = self.COLORS["amber"]
        else:
            color = self.COLORS["emerald"]
        self.risk_number_label.configure(text=f"{round(value)} / 100", text_color=color)
        self.risk_progress.configure(progress_color=color)
        self.risk_progress.set(value / 100)

    def _style_axes(self, axes: Any) -> None:
        axes.set_facecolor(self.COLORS["surface"])
        axes.tick_params(colors=self.COLORS["muted"], labelsize=8)
        for spine in axes.spines.values():
            spine.set_color(self.COLORS["border"])
        axes.grid(axis="y", color="#1B2C43", linewidth=0.7, alpha=0.7)

    def _draw_entropy(self, indices: list[int], values: list[float]) -> None:
        axes = self.entropy_axes
        axes.clear()
        self._style_axes(axes)
        axes.set_ylim(0, 8.5)
        axes.set_ylabel("bits / byte", color=self.COLORS["muted"], fontsize=8)
        axes.set_xlabel("block index", color=self.COLORS["muted"], fontsize=8)
        if values:
            axes.fill_between(indices, values, color=self.COLORS["cyan"], alpha=0.13)
            axes.plot(indices, values, color=self.COLORS["cyan"], linewidth=1.8)
            axes.scatter(indices, values, color="#A5F3FC", s=9, zorder=3)
        else:
            axes.text(
                0.5,
                0.5,
                "No local entropy result selected",
                color=self.COLORS["muted"],
                ha="center",
                va="center",
                transform=axes.transAxes,
                fontsize=9,
            )
        self.entropy_figure.tight_layout(pad=1.0)
        self.entropy_canvas.draw_idle()

    def _draw_telemetry(self, source_counts: dict[str, int], risk_bands: dict[str, int]) -> None:
        axes = self.telemetry_axes
        axes.clear()
        self._style_axes(axes)
        labels = ["low", "elevated", "high"]
        values = [max(0, int(risk_bands.get(label, 0))) for label in labels]
        bars = axes.bar(
            labels,
            values,
            color=[self.COLORS["emerald"], self.COLORS["amber"], self.COLORS["rose"]],
            width=0.55,
        )
        axes.set_ylabel("scored events", color=self.COLORS["muted"], fontsize=8)
        axes.set_ylim(0, max(1, max(values) + 1))
        for bar, value in zip(bars, values):
            axes.text(
                bar.get_x() + bar.get_width() / 2,
                value + 0.05,
                str(value),
                ha="center",
                va="bottom",
                color=self.COLORS["ink"],
                fontsize=8,
            )
        if source_counts:
            compact_sources = ", ".join(f"{name}: {count}" for name, count in list(source_counts.items())[:3])
            axes.set_title(compact_sources, color=self.COLORS["muted"], fontsize=7, loc="left", pad=7)
        else:
            axes.set_title("No event sources reported", color=self.COLORS["muted"], fontsize=8, loc="left", pad=7)
        self.telemetry_figure.tight_layout(pad=1.0)
        self.telemetry_canvas.draw_idle()

    # Window and operation lifecycle -----------------------------------------
    def set_busy(self, busy: bool, message: str = "") -> None:
        state = "disabled" if busy else "normal"
        for button in (
            self.refresh_button,
            self.scan_button,
            self.quarantine_button,
            self.restore_button,
        ):
            button.configure(state=state)
        if busy:
            self._busy_tick = 0
            self._animate_busy(message or "Working with local engine")
        else:
            if self._busy_animation_job is not None:
                self.after_cancel(self._busy_animation_job)
                self._busy_animation_job = None
            self.busy_label.configure(text="LOCAL-ONLY · NO CLOUD TELEMETRY", text_color=self.COLORS["muted"])

    def _animate_busy(self, message: str) -> None:
        if self._busy_animation_job is not None:
            self.after_cancel(self._busy_animation_job)
        dots = "." * ((self._busy_tick % 3) + 1)
        self.busy_label.configure(text=f"{message}{dots}", text_color=self.COLORS["cyan"])
        self._busy_tick += 1
        self._busy_animation_job = self.after(330, lambda: self._animate_busy(message))

    def schedule(self, delay_ms: int, callback: Callable[[], None]) -> Any:
        return self.after(delay_ms, callback)

    def dispatch(self, callback: Callable[[], None]) -> Any:
        return self.after(0, callback)

    def close(self) -> None:
        if self._risk_animation_job is not None:
            self.after_cancel(self._risk_animation_job)
        if self._busy_animation_job is not None:
            self.after_cancel(self._busy_animation_job)
        self._save_geometry()
        self.destroy()

    def _request_close(self) -> None:
        if self._closing_callback is not None:
            self._closing_callback()
        else:
            self.close()

    @staticmethod
    def _replace_text(widget: Any, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    @staticmethod
    def _settings_path() -> Path:
        if os.name == "nt":
            base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        return base / "elliot" / "gui.json"

    def _load_geometry(self) -> None:
        path = self._settings_path()
        try:
            with path.open("r", encoding="utf-8") as stream:
                data = json.load(stream)
            geometry = data.get("geometry")
            if isinstance(geometry, str) and 4 <= len(geometry) <= 100:
                self.geometry(geometry)
                return
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            logger.warning("Could not load GUI settings: %s", exc)
        self._center_window()

    def _save_geometry(self) -> None:
        path = self._settings_path()
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(path.parent, 0o700)
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump({"geometry": self.geometry()}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except OSError as exc:
            logger.warning("Could not save GUI settings: %s", exc)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _center_window(self) -> None:
        width, height = 1280, 860
        self.update_idletasks()
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")


# Kept for scripts and integrations that still import the Stage 7 class name.
PardusView = ElliotView
