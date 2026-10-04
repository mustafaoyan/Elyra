"""Small native Windows GUI for the local Elyra AI assistant."""

from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .analyst import EvidenceAnalyst
from .updater import check_for_update, download_and_launch

CURRENT_VERSION = "1.0.8"


class AssistantWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ELYRA AI Assistant")
        self.geometry("820x600")
        self.minsize(680, 460)
        self.analyst = EvidenceAnalyst()
        self._build_ui()
        self.after(250, self._check_update)

    def _build_ui(self) -> None:
        self.configure(bg="#08111f")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TButton", padding=8)
        style.configure("TLabel", background="#08111f", foreground="#dbeafe")
        header = ttk.Frame(self, padding=18)
        header.pack(fill="x")
        ttk.Label(header, text="ELYRA AI ASSISTANT", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(header, text="Yerel kanıt analizi · Bulut bağlantısı yok · Dosya çalıştırmaz").pack(anchor="w", pady=(4, 0))
        self.output = tk.Text(self, bg="#0f1d31", fg="#e5f2ff", insertbackground="white", wrap="word", relief="flat", padx=16, pady=16)
        self.output.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self.output.insert("end", "Elyra AI hazır. Bir kanıt JSON dosyası seçin veya aşağıya soru yazın.\n\n")
        controls = ttk.Frame(self, padding=(18, 0, 18, 18))
        controls.pack(fill="x")
        self.question = ttk.Entry(controls)
        self.question.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.question.bind("<Return>", lambda _event: self._answer())
        ttk.Button(controls, text="Gönder", command=self._answer).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Kanıt JSON aç", command=self._choose_evidence).pack(side="left")

    def _write(self, text: str) -> None:
        self.output.insert("end", text + "\n")
        self.output.see("end")

    def _answer(self) -> None:
        text = self.question.get().strip()
        if not text:
            return
        self.question.delete(0, "end")
        self._write(f"Sen: {text}")
        self._write("Elyra: Bu sürüm yalnızca kanıt JSON dosyalarını açıklayabilir. 'Kanıt JSON aç' düğmesini kullanın.\n")

    def _choose_evidence(self) -> None:
        filename = filedialog.askopenfilename(title="Elyra kanıt JSON dosyası seçin", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not filename:
            return
        try:
            evidence = json.loads(Path(filename).read_text(encoding="utf-8-sig"))
            result = self.analyst.analyze(evidence)
            self._write(f"Kanıt: {filename}\n{json.dumps(result, ensure_ascii=False, indent=2)}\n")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("Analiz başarısız", str(exc))

    def _check_update(self) -> None:
        try:
            update = check_for_update(CURRENT_VERSION)
            if update and messagebox.askyesno("Elyra güncellemesi", f"Yeni sürüm mevcut: {update.latest_version}. Şimdi indirip kurulsun mu?"):
                download_and_launch(update)
                messagebox.showinfo("Kurulum başlatıldı", "Yeni kurulum başlatıldı. Kurulum tamamlanınca Elyra'yı yeniden açın.")
        except Exception:
            # Network/update errors must never prevent the local app from opening.
            pass


def main() -> int:
    AssistantWindow().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
