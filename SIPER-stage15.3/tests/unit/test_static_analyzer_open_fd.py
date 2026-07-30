from __future__ import annotations

import os

from elliot.analyzer.static_analyzer import StaticFileScanner


def test_scan_open_fd_uses_descriptor_bytes_and_original_path_context(tmp_path):
    candidate = tmp_path / ".safe.txt"
    candidate.write_bytes(b"ordinary harmless text\n" * 20)
    fd = os.open(candidate, os.O_RDONLY)
    try:
        result = StaticFileScanner().scan_open_fd(fd, str(candidate))
    finally:
        os.close(fd)

    assert result.status == "OK"
    assert result.filepath == str(candidate)
    assert result.extension == ".txt"
    assert result.path_context["hidden"] is True
    assert result.entropy_summary["bytes_analyzed"] == candidate.stat().st_size
