from pathlib import Path


def test_active_gui_and_service_sources_do_not_use_obsolete_tcp_or_tmp_socket() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "elliot"
    sources = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.py"))
    assert "127.0.0.1" not in sources
    assert "65432" not in sources
    assert "elliot_ebpf_gui.sock" not in sources
    assert "socket.AF_INET" not in sources
