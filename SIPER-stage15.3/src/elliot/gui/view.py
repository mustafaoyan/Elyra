"""CustomTkinter view for real Siper daemon data.

The production view does not generate random telemetry or pretend unavailable
components are active. A separately labelled safe-demo banner may be supplied by
the demonstration launcher.
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
except ImportError as exc:  # Keep package imports safe in headless/minimal environments.
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


class PardusView(_BaseView):
    def __init__(self, *, banner_text: str | None = None) -> None:
        if ctk is None:
            raise RuntimeError(
                "GUI dependencies are unavailable; install customtkinter, matplotlib and Tkinter"
            ) from GUI_IMPORT_ERROR
        super().__init__()
        self._banner_text = banner_text
        self._quarantine_ids_by_label: dict[str, str] = {}
        self._closing_callback: Callable[[], None] | None = None

        self.title("Siper — Pardus Security Monitor")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self._load_geometry()
        self.protocol("WM_DELETE_WINDOW", self._request_close)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main_dashboard()

    def _build_sidebar(self) -> None:
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(10, weight=1)

        ctk.CTkLabel(
            self.sidebar,
            text="SIPER",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).grid(row=0, column=0, padx=20, pady=(20, 4))
        ctk.CTkLabel(
            self.sidebar,
            text="Pardus Defence Engine",
            text_color="#aab2bd",
        ).grid(row=1, column=0, padx=20, pady=(0, 14))

        if self._banner_text:
            self.demo_banner = ctk.CTkLabel(
                self.sidebar,
                text=self._banner_text,
                wraplength=205,
                text_color="#f4d03f",
                font=ctk.CTkFont(size=12, weight="bold"),
            )
            self.demo_banner.grid(row=2, column=0, padx=12, pady=6)

        self.status_label = ctk.CTkLabel(
            self.sidebar,
            text="Service: CHECKING",
            text_color="#f4d03f",
            font=ctk.CTkFont(weight="bold"),
        )
        self.status_label.grid(row=3, column=0, padx=20, pady=(12, 4))

        self.component_label = ctk.CTkLabel(
            self.sidebar,
            text="fanotify: unknown\neBPF: unknown",
            justify="left",
        )
        self.component_label.grid(row=4, column=0, padx=20, pady=4)

        self.policy_label = ctk.CTkLabel(self.sidebar, text="Policy: UNKNOWN")
        self.policy_label.grid(row=5, column=0, padx=20, pady=4)

        self.error_label = ctk.CTkLabel(
            self.sidebar,
            text="",
            wraplength=205,
            text_color="#ec7063",
        )
        self.error_label.grid(row=6, column=0, padx=12, pady=4)

        self.refresh_button = ctk.CTkButton(self.sidebar, text="Refresh")
        self.refresh_button.grid(row=7, column=0, padx=20, pady=(12, 6))
        self.scan_button = ctk.CTkButton(self.sidebar, text="Scan File")
        self.scan_button.grid(row=8, column=0, padx=20, pady=6)
        self.quarantine_button = ctk.CTkButton(
            self.sidebar,
            text="Refresh Quarantine",
            fg_color="#b9770e",
            hover_color="#9c640c",
        )
        self.quarantine_button.grid(row=9, column=0, padx=20, pady=6)

        self.busy_label = ctk.CTkLabel(self.sidebar, text="", text_color="#85c1e9")
        self.busy_label.grid(row=11, column=0, padx=12, pady=12)

    def _build_main_dashboard(self) -> None:
        self.main = ctk.CTkFrame(self)
        self.main.grid(row=0, column=1, padx=14, pady=14, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(3, weight=1)

        self.score_header = ctk.CTkLabel(
            self.main,
            text="Pre-execution score: N/A | Runtime score: N/A | Decision: N/A",
            font=ctk.CTkFont(size=17, weight="bold"),
        )
        self.score_header.grid(row=0, column=0, padx=18, pady=(16, 5), sticky="w")

        self.score_progress = ctk.CTkProgressBar(self.main, height=18)
        self.score_progress.grid(row=1, column=0, padx=18, pady=5, sticky="ew")
        self.score_progress.set(0)

        self.file_summary = ctk.CTkLabel(
            self.main,
            text="No file has been scanned in this GUI session.",
            anchor="w",
            justify="left",
        )
        self.file_summary.grid(row=2, column=0, padx=18, pady=5, sticky="ew")

        self.tabs = ctk.CTkTabview(self.main)
        self.tabs.grid(row=3, column=0, padx=14, pady=12, sticky="nsew")
        for name in ("Analysis", "Events", "Quarantine"):
            self.tabs.add(name)

        analysis_tab = self.tabs.tab("Analysis")
        analysis_tab.grid_columnconfigure(0, weight=1)
        analysis_tab.grid_rowconfigure(0, weight=1)
        analysis_tab.grid_rowconfigure(1, weight=1)

        self.graph_frame = ctk.CTkFrame(analysis_tab, height=260)
        self.graph_frame.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self.fig = Figure(figsize=(7.5, 2.8), dpi=100, facecolor="#2b2b2b")
        self.ax = self.fig.add_subplot(111)
        self._style_axes()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self._draw_entropy([], [])

        self.analysis_text = ctk.CTkTextbox(
            analysis_tab,
            font=ctk.CTkFont(family="monospace", size=12),
        )
        self.analysis_text.grid(row=1, column=0, padx=8, pady=8, sticky="nsew")
        self._replace_text(
            self.analysis_text,
            "Waiting for a real scan result from the Siper daemon.\n",
        )

        events_tab = self.tabs.tab("Events")
        events_tab.grid_columnconfigure(0, weight=1)
        events_tab.grid_rowconfigure(0, weight=1)
        self.events_text = ctk.CTkTextbox(
            events_tab,
            font=ctk.CTkFont(family="monospace", size=12),
        )
        self.events_text.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self._replace_text(self.events_text, "No daemon events available.\n")

        quarantine_tab = self.tabs.tab("Quarantine")
        quarantine_tab.grid_columnconfigure(0, weight=1)
        quarantine_tab.grid_rowconfigure(1, weight=1)
        self.quarantine_selector = ctk.CTkOptionMenu(
            quarantine_tab,
            values=["No quarantine records"],
        )
        self.quarantine_selector.grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        self.quarantine_text = ctk.CTkTextbox(
            quarantine_tab,
            font=ctk.CTkFont(family="monospace", size=12),
        )
        self.quarantine_text.grid(row=1, column=0, padx=8, pady=8, sticky="nsew")
        self.restore_button = ctk.CTkButton(
            quarantine_tab,
            text="Restore Selected to Original Path",
            fg_color="#2874a6",
            hover_color="#21618c",
        )
        self.restore_button.grid(row=2, column=0, padx=8, pady=8, sticky="e")

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

    def render_dashboard(self, snapshot: dict[str, Any]) -> None:
        projection = dashboard_projection(snapshot)
        state = projection["service_state"]
        color = {
            "CONNECTED": "#58d68d",
            "DEGRADED": "#f4d03f",
            "DISCONNECTED": "#ec7063",
        }[state]
        self.status_label.configure(text=f"Service: {state}", text_color=color)
        components = projection["component_states"]
        self.component_label.configure(
            text=(
                f"fanotify: {'active' if components['fanotify'] else 'unavailable'}\n"
                f"eBPF: {'active' if components['ebpf'] else 'unavailable'}"
            )
        )
        self.policy_label.configure(text=f"Policy: {projection['policy_mode']}")

        degraded = projection["degraded_components"]
        error_lines = [
            f"{item.get('section')}: {item.get('code')} — {item.get('message')}"
            for item in projection["errors"]
        ]
        if degraded:
            error_lines.insert(0, "Degraded: " + ", ".join(degraded))
        self.error_label.configure(text="\n".join(error_lines[:4]))

        event_lines = [format_event(event) for event in projection["events"]]
        self._replace_text(
            self.events_text,
            "\n".join(event_lines) + ("\n" if event_lines else "No daemon events available.\n"),
        )
        self._render_quarantine(projection["quarantine"])

    def render_scan_result(self, result: dict[str, Any]) -> None:
        view = scan_projection(result)
        score = max(0, min(100, int(view["pre_execution_score"])))
        runtime = view["runtime_score"]
        runtime_text = "N/A" if runtime is None else str(runtime)
        self.score_header.configure(
            text=(
                f"Pre-execution score: {score}/100 | Runtime score: {runtime_text} "
                f"| Decision: {view['decision']}"
            )
        )
        self.score_progress.set(score / 100.0)
        if score >= 70:
            self.score_progress.configure(progress_color="#e74c3c")
        elif score >= 40:
            self.score_progress.configure(progress_color="#f1c40f")
        else:
            self.score_progress.configure(progress_color="#2ecc71")

        whole_entropy = view["whole_file_entropy"]
        entropy_text = "N/A" if whole_entropy is None else f"{whole_entropy} bits/byte"
        self.file_summary.configure(
            text=(
                f"File: {view['filepath']}\nMIME: {view['mime_type']} | "
                f"MIME/extension: {view['mime_extension_consistency']} | "
                f"ELF: {view['is_elf']} | Whole entropy: {entropy_text}"
            )
        )
        self._draw_entropy(view["block_indices"], view["block_entropies"])

        lines = [
            f"Status: {view['status']}",
            f"Decision: {view['decision']}",
            f"Analysis duration: {view['duration_ms']:.3f} ms",
            "",
            "Triggered rules:",
        ]
        indicators = view["indicators"]
        lines.extend(format_indicator(item) for item in indicators)
        if not indicators:
            lines.append("None")
        if view["warnings"]:
            lines.extend(["", "Warnings:"])
            lines.extend(str(item) for item in view["warnings"])
        if view["errors"]:
            lines.extend(["", "Errors:"])
            lines.extend(str(item) for item in view["errors"])
        if view["blocks_truncated"]:
            lines.extend(["", "Block graph is sampled because the complete block list is large."])
        self._replace_text(self.analysis_text, "\n".join(lines) + "\n")
        self.tabs.set("Analysis")

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

    def set_busy(self, busy: bool, message: str = "") -> None:
        state = "disabled" if busy else "normal"
        for button in (
            self.refresh_button,
            self.scan_button,
            self.quarantine_button,
            self.restore_button,
        ):
            button.configure(state=state)
        self.busy_label.configure(text=message if busy else "")

    def schedule(self, delay_ms: int, callback: Callable[[], None]) -> Any:
        return self.after(delay_ms, callback)

    def dispatch(self, callback: Callable[[], None]) -> Any:
        return self.after(0, callback)

    def close(self) -> None:
        self._save_geometry()
        self.destroy()

    def _request_close(self) -> None:
        if self._closing_callback is not None:
            self._closing_callback()
        else:
            self.close()

    def _style_axes(self) -> None:
        self.ax.set_facecolor("#2b2b2b")
        self.ax.tick_params(colors="white")
        for spine in self.ax.spines.values():
            spine.set_color("#555555")

    def _draw_entropy(self, indices: list[int], values: list[float]) -> None:
        self.ax.clear()
        self._style_axes()
        self.ax.set_ylim(0, 8.5)
        self.ax.set_title("Real block-level Shannon entropy", color="white", fontsize=10)
        self.ax.set_xlabel("Block index", color="white")
        self.ax.set_ylabel("bits/byte", color="white")
        if values:
            self.ax.plot(indices, values, marker="o", markersize=3, linewidth=1.5)
        else:
            self.ax.text(
                0.5,
                0.5,
                "No real block-entropy data available",
                color="white",
                ha="center",
                va="center",
                transform=self.ax.transAxes,
            )
        self.canvas.draw()

    @staticmethod
    def _replace_text(widget: Any, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    @staticmethod
    def _settings_path() -> Path:
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
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(path.parent, 0o700)
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump({"geometry": self.geometry()}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except OSError as exc:
            logger.warning("Could not save GUI settings: %s", exc)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _center_window(self) -> None:
        width, height = 1180, 820
        self.update_idletasks()
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
