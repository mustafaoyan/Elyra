"""First-run downloader for Elyra's embedded GGUF chat model."""

from __future__ import annotations

import os
import tempfile
import urllib.request
from pathlib import Path

MODEL_FILENAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
MODEL_URL = "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf?download=true"


def default_model_path() -> Path:
    configured = os.environ.get("ELYRA_CHAT_MODEL")
    return Path(configured) if configured else Path.home() / ".elyra" / "models" / "chat" / "model.gguf"


def download_model(target: Path | None = None, progress=None) -> Path:
    destination = target or default_model_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkstemp(prefix="elyra-model-", suffix=".part", dir=destination.parent)[1])
    try:
        request = urllib.request.Request(MODEL_URL, headers={"User-Agent": "Elyra-AI/1.0"})
        with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as output:
            total = int(response.headers.get("Content-Length", "0"))
            received = 0
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                received += len(chunk)
                if progress and total:
                    progress(received / total)
        temporary.replace(destination)
        return destination
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
