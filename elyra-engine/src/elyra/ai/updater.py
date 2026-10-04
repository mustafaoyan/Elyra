"""Safe GitHub Release updater for the local Elyra AI Assistant."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPOSITORY = "mustafaoyan/Elyra"
API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
TIMEOUT_SECONDS = 3


@dataclass(frozen=True)
class UpdateInfo:
    current_version: str
    latest_version: str
    installer_url: str
    installer_name: str
    checksum_url: str | None


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = value.removeprefix("v").split(".")
    try:
        return tuple(int(part) for part in parts[:3])
    except ValueError:
        return (0,)


def _read_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "Elyra-AI-Updater"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("release response is not an object")
    return value


def check_for_update(current_version: str) -> UpdateInfo | None:
    """Return a Windows installer update, or None when unavailable/current."""
    if os.environ.get("ELYRA_DISABLE_UPDATE_CHECK") == "1":
        return None
    if platform.system() != "Windows":
        return None
    release = _read_json(API_URL)
    tag = str(release.get("tag_name", ""))
    latest = tag.removeprefix("v")
    if not latest or _version_tuple(latest) <= _version_tuple(current_version):
        return None
    assets = release.get("assets")
    if not isinstance(assets, list):
        return None
    wanted = f"ELYRA-AI-Setup-{latest}-x64.exe"
    installer_url = checksum_url = None
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name", ""))
        url = str(asset.get("browser_download_url", ""))
        if name == wanted and url.startswith("https://github.com/"):
            installer_url = url
        if name == "SHA256SUMS.txt" and url.startswith("https://github.com/"):
            checksum_url = url
    if not installer_url:
        return None
    return UpdateInfo(current_version, latest, installer_url, wanted, checksum_url)


def _download(url: str, target: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "Elyra-AI-Updater"})
    with urllib.request.urlopen(request, timeout=30) as response, target.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)


def download_and_launch(info: UpdateInfo) -> Path:
    """Download, verify, and start the signed-by-release installer."""
    directory = Path(tempfile.mkdtemp(prefix="elyra-ai-update-"))
    installer = directory / info.installer_name
    _download(info.installer_url, installer)
    if info.checksum_url:
        checksum_text = directory / "SHA256SUMS.txt"
        _download(info.checksum_url, checksum_text)
        expected = next((line.split()[0] for line in checksum_text.read_text(encoding="utf-8").splitlines() if info.installer_name in line), "")
        actual = hashlib.sha256(installer.read_bytes()).hexdigest()
        if not expected or expected.lower() != actual.lower():
            raise ValueError("installer checksum verification failed")
    subprocess.Popen([str(installer)], close_fds=True)
    return installer
