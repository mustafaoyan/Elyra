#!/usr/bin/env python3
"""Build the installable Windows ELYRA AI Assistant setup executable."""
from __future__ import annotations
import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("Windows packaging must run on Windows")
    pyinstaller = shutil.which("pyinstaller") or shutil.which("pyinstaller.exe")
    iscc = shutil.which("ISCC") or shutil.which("ISCC.exe")
    if not pyinstaller or not iscc:
        parser.error("PyInstaller and Inno Setup (ISCC.exe) are required")
    dist = PROJECT_ROOT / "dist"
    app_dist, build, installer_dist = dist / "ELYRA-AI", PROJECT_ROOT / "build" / "windows-ai", dist / "windows-ai"
    if args.clean:
        for path in (app_dist, build, installer_dist):
            if path.exists(): shutil.rmtree(path)
    command = [pyinstaller, "--noconfirm", "--clean", "--windowed", "--name", "ELYRA-AI", "--paths", str(PROJECT_ROOT / "src"), "--distpath", str(dist), "--workpath", str(build), str(PROJECT_ROOT / "packaging" / "windows" / "elyra_ai.py")]
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)
    template = (PROJECT_ROOT / "packaging" / "windows" / "ELYRA-AI.iss").read_text(encoding="utf-8")
    generated = build / "ELYRA-AI.generated.iss"
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text(template.replace("@VERSION@", args.version), encoding="utf-8")
    subprocess.run([iscc, str(generated)], cwd=PROJECT_ROOT, check=True)
    installer = installer_dist / f"ELYRA-AI-Setup-{args.version}-x64.exe"
    if not installer.is_file(): raise RuntimeError(f"Installer was not created: {installer}")
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    (installer_dist / "SHA256SUMS.txt").write_text(f"{digest} *{installer.name}\n", encoding="utf-8")
    print(f"Built installer: {installer}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
