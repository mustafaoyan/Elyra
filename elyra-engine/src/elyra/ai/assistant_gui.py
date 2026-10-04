"""Futuristic, local-only Elyra AI desktop chat interface."""

from __future__ import annotations

import json
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from .analyst import EvidenceAnalyst
from .chat_engine import ChatEngineUnavailable, LocalChatEngine
from .model_manager import download_model
from .updater import check_for_update, download_and_launch

CURRENT_VERSION = "1.1.1"
BG = "#0B0C10"
PANEL = "#11141D"
PANEL_ALT = "#161B27"
NEON = "#66FCF1"
CYAN = "#00CFFF"
TEXT = "#E8F7FF"
MUTED = "#8EA7B8"


class AssistantWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ELYRA // LOCAL AI ASSISTANT")
        self.geometry("980x700")
        self.minsize(720, 520)
        self.configure(bg=BG)
        self.analyst = EvidenceAnalyst()
        self.chat = LocalChatEngine()
        self._active = False
        self._sidebar_open = False
        self._icon_path = self._find_icon()
        if self._icon_path:
            self.iconbitmap(default=str(self._icon_path))
        self._build_ui()
        self.after(250, self._check_update)

    @staticmethod
    def _find_icon() -> Path | None:
        roots = [Path(getattr(sys, "_MEIPASS", "")), Path(__file__).resolve().parents[3]]
        for root in roots:
            if not root:
                continue
            for candidate in (root / "elyra.ico", root / "packaging" / "windows" / "elyra.ico"):
                if candidate.is_file():
                    return candidate
        return None

    def _button(self, parent: tk.Misc, text: str, command, *, accent: bool = False) -> tk.Button:
        return tk.Button(parent, text=text, command=command, bg=NEON if accent else PANEL_ALT,
                         fg=BG if accent else TEXT, activebackground=CYAN, activeforeground=BG,
                         relief="flat", bd=0, cursor="hand2", font=("Segoe UI", 10, "bold"),
                         padx=14, pady=9)

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=BG, height=66)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        self._button(header, "☰", self._toggle_sidebar).pack(side="left", padx=18, pady=14)
        tk.Label(header, text="ELYRA", bg=BG, fg=NEON, font=("Segoe UI", 17, "bold")).pack(side="left")
        tk.Label(header, text="  /  LOCAL INTELLIGENCE", bg=BG, fg=MUTED, font=("Consolas", 10)).pack(side="left")
        tk.Label(header, text="●  OFFLINE CORE", bg=BG, fg=NEON, font=("Consolas", 9, "bold")).pack(side="right", padx=22)

        self.body = tk.Frame(self, bg=BG)
        self.body.pack(fill="both", expand=True)
        self.output = tk.Text(self.body, bg=BG, fg=TEXT, insertbackground=NEON, wrap="word", relief="flat",
                              padx=38, pady=28, font=("Segoe UI", 11), spacing3=8)
        self.output.pack(fill="both", expand=True)
        self.output.tag_configure("user", foreground=NEON, font=("Segoe UI", 11, "bold"))
        self.output.tag_configure("assistant", foreground=TEXT)
        self.output.tag_configure("system", foreground=MUTED, font=("Consolas", 9))
        self.output.insert("end", "SYSTEM ONLINE\n", "system")
        self.output.insert("end", "Elyra AI hazır. Nasıl yardımcı olabilirim?\n", "assistant")

        self.composer = tk.Frame(self, bg=PANEL, highlightbackground=NEON, highlightthickness=1)
        self.composer.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.72, height=58)
        self.question = tk.Entry(self.composer, bg=PANEL, fg=TEXT, insertbackground=NEON,
                                 relief="flat", font=("Segoe UI", 12))
        self.question.pack(side="left", fill="both", expand=True, padx=(16, 8), pady=8)
        self.question.bind("<Return>", lambda _event: self._answer())
        self._button(self.composer, "SEND  ↗", self._answer, accent=True).pack(side="right", padx=6, pady=6)
        self.action_bar = tk.Frame(self, bg=BG)
        self._button(self.action_bar, "Open evidence JSON", self._choose_evidence).pack(side="left", padx=4)
        self.model_button = self._button(self.action_bar, "Install local model", self._install_model)
        self.model_button.pack(side="left", padx=4)

        self.sidebar = tk.Frame(self, bg=PANEL, width=270, highlightbackground=CYAN, highlightthickness=1)
        self.sidebar.place(x=-270, y=0, relheight=1)
        tk.Label(self.sidebar, text="PROFILE", bg=PANEL, fg=MUTED, font=("Consolas", 9, "bold")).pack(pady=(30, 8))
        tk.Canvas(self.sidebar, width=84, height=84, bg=PANEL, highlightthickness=2, highlightbackground=NEON).pack()
        tk.Label(self.sidebar, text="LOCAL OPERATOR", bg=PANEL, fg=TEXT, font=("Segoe UI", 11, "bold")).pack(pady=10)
        self._button(self.sidebar, "Settings  ⚙", self._settings).place(relx=0.08, rely=0.94, relwidth=0.84, anchor="sw")

    def _toggle_sidebar(self) -> None:
        target = 0 if not self._sidebar_open else -270
        self._sidebar_open = not self._sidebar_open
        self._slide_sidebar(target)

    def _slide_sidebar(self, target: int) -> None:
        current = self.sidebar.winfo_x()
        if current == target:
            return
        step = 30 if target > current else -30
        next_x = current + step
        if (step > 0 and next_x > target) or (step < 0 and next_x < target):
            next_x = target
        self.sidebar.place_configure(x=next_x)
        if next_x != target:
            self.after(12, lambda: self._slide_sidebar(target))

    def _activate_chat(self) -> None:
        if self._active:
            return
        self._active = True
        self.composer.place_forget()
        self.composer.pack(fill="x", side="bottom", padx=28, pady=(0, 12), ipady=2)
        self.action_bar.pack(fill="x", side="bottom", padx=28, pady=(0, 14))

    def _write(self, text: str, tag: str = "assistant") -> None:
        self.output.insert("end", text + "\n", tag)
        self.output.see("end")

    def _answer(self) -> None:
        text = self.question.get().strip()
        if not text:
            return
        self._activate_chat()
        self.question.delete(0, "end")
        self._write(f"YOU  ›  {text}", "user")
        try:
            self._write(f"ELYRA  ›  {self.chat.respond(text)}", "assistant")
        except ChatEngineUnavailable:
            self._write("ELYRA  ›  Yerel sohbet modeli henüz kurulmamış. 'Install local model' düğmesini kullanın.", "system")

    def _choose_evidence(self) -> None:
        filename = filedialog.askopenfilename(title="Select Elyra evidence JSON", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not filename:
            return
        self._activate_chat()
        try:
            evidence = json.loads(Path(filename).read_text(encoding="utf-8-sig"))
            result = self.analyst.analyze(evidence)
            self._write(f"EVIDENCE  ›  {filename}\n{json.dumps(result, ensure_ascii=False, indent=2)}", "assistant")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("Analysis failed", str(exc))

    def _install_model(self) -> None:
        if self.chat.available:
            messagebox.showinfo("Model ready", "The local chat model is already installed.")
            return
        if not messagebox.askyesno("Install local model", "Download the approximately 1.1 GB local model now?"):
            return
        self.model_button.configure(state="disabled", text="DOWNLOADING...")

        def worker() -> None:
            try:
                path = download_model()
                self.after(0, lambda: self._model_ready(path))
            except Exception as exc:
                self.after(0, lambda: self._model_failed(exc))

        threading.Thread(target=worker, daemon=True).start()

    def _model_ready(self, path: Path) -> None:
        self.model_button.configure(state="normal", text="MODEL READY")
        self.chat = LocalChatEngine(path)
        messagebox.showinfo("Model ready", "Elyra can now chat locally.")

    def _model_failed(self, error: Exception) -> None:
        self.model_button.configure(state="normal", text="Install local model")
        messagebox.showerror("Model download failed", str(error))

    def _settings(self) -> None:
        messagebox.showinfo("Settings", "Settings panel will be connected to local policy controls in the next UI milestone.")

    def _check_update(self) -> None:
        try:
            update = check_for_update(CURRENT_VERSION)
            if update and messagebox.askyesno("Elyra update", f"New version: {update.latest_version}. Download and install now?"):
                download_and_launch(update)
                messagebox.showinfo("Installer started", "The new installer has started. Reopen Elyra after installation.")
        except Exception:
            pass


def main() -> int:
    AssistantWindow().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
