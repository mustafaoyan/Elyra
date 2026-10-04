"""Embedded local chat engine boundary for Elyra.

The GUI talks to this class directly. No Ollama process, cloud API, or remote
service is required. A GGUF model can be loaded through the optional embedded
llama.cpp Python binding when it is present in the Elyra environment.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


class ChatEngineUnavailable(RuntimeError):
    """Raised when the local language model is not installed yet."""


class LocalChatEngine:
    def __init__(self, model_path: str | Path | None = None) -> None:
        configured = model_path or os.environ.get("ELYRA_CHAT_MODEL")
        self.model_path = Path(configured) if configured else Path.home() / ".elyra" / "models" / "chat" / "model.gguf"
        self._model: Any = None
        self._history: list[dict[str, str]] = []

    @property
    def available(self) -> bool:
        return self.model_path.is_file()

    def _load(self) -> Any:
        if self._model is not None:
            return self._model
        if not self.available:
            raise ChatEngineUnavailable(f"Yerel sohbet modeli bulunamadı: {self.model_path}")
        try:
            from llama_cpp import Llama  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ChatEngineUnavailable("Elyra embedded chat runtime is not installed") from exc
        self._model = Llama(model_path=str(self.model_path), n_ctx=4096, verbose=False)
        return self._model

    def respond(self, message: str, *, security_context: dict[str, Any] | None = None) -> str:
        clean = message.strip()
        if not clean or len(clean) > 2000:
            raise ValueError("message must contain 1-2000 characters")
        model = self._load()
        system = (
            "You are Elyra, a local cybersecurity assistant. Explain evidence clearly. "
            "Never claim certainty from one signal, never execute files, and never invent scan results."
        )
        if security_context:
            system += "\nTrusted scanner context (explain only; do not change it): " + str(security_context)[:4000]
        self._history.extend(({"role": "user", "content": clean},))
        response = model.create_chat_completion(
            [{"role": "system", "content": system}, *self._history[-12:]],
            temperature=0.2,
            max_tokens=512,
        )
        answer = str(response["choices"][0]["message"]["content"]).strip()
        self._history.append({"role": "assistant", "content": answer})
        return answer

    def reset(self) -> None:
        self._history.clear()
