#!/usr/bin/env python3
"""Create a reproducible local ELYRA Windows executable and installer.

Run this on 64-bit Windows after installing PyInstaller and Inno Setup.  The
script never uploads artifacts; release publication and code signing remain
explicit release-owner actions.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str], *, cwd: Path) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=cwd, check=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release version, for example 1.1.0")
    parser.add_argument("--clean", action="store_true", help="remove only this script's dist/build directories")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("Windows packaging must run on Windows")
    if not args.version.replace(".", "").replace("-", "").isalnum():
        parser.error("--version may contain only letters, digits, dots and hyphens")

    pyinstaller = shutil.which("pyinstaller") or shutil.which("pyinstaller.exe")
    iscc = shutil.which("ISCC") or shutil.which("ISCC.exe")
    if not pyinstaller:
        parser.error("PyInstaller is required; install it in the active build environment")
    if not iscc:
        parser.error("Inno Setup Compiler (ISCC.exe) is required to create the installer")

    dist_root = PROJECT_ROOT / "dist"
    build_root = PROJECT_ROOT / "build" / "windows"
    app_dist = dist_root / "ELYRA"
    installer_dist = dist_root / "windows"
    if args.clean:
        for path in (app_dist, build_root, installer_dist):
            if path.exists():
                shutil.rmtree(path)

    entrypoint = PROJECT_ROOT / "packaging" / "windows" / "elyra_gui.py"
    _run(
        [
            pyinstaller,
            "--noconfirm",
            "--clean",
            "--windowed",
            "--name",
            "ELYRA",
            "--paths",
            str(PROJECT_ROOT / "src"),
            "--distpath",
            str(dist_root),
            "--workpath",
            str(build_root),
            str(entrypoint),
        ],
        cwd=PROJECT_ROOT,
    )
    template = (PROJECT_ROOT / "packaging" / "windows" / "ELYRA.iss").read_text(encoding="utf-8")
    generated = build_root / "ELYRA.generated.iss"
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text(template.replace("@VERSION@", args.version), encoding="utf-8")
    _run([iscc, str(generated)], cwd=PROJECT_ROOT)

    installer = installer_dist / f"ELYRA-Setup-{args.version}-x64.exe"
    if not installer.is_file():
        raise RuntimeError(f"Inno Setup did not create expected installer: {installer}")
    checksum_file = installer_dist / "SHA256SUMS.txt"
    checksum_file.write_text(f"{_sha256(installer)} *{installer.name}\n", encoding="utf-8")
    print(f"Built installer: {installer}")
    print(f"Checksum: {checksum_file}")
    print("Sign the installer and publish both files to a GitHub Release before enabling downloads.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
