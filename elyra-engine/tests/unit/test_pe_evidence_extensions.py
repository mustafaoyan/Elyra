import struct

from elyra.analyzer.pe import analyze_pe
from test_pe_analysis import _pe_bytes, _write


def test_data_directory_presence_is_reported_without_parsing_payload(tmp_path):
    data = _pe_bytes()
    # PE32 import directory: RVA and size only; no import names are read.
    struct.pack_into("<II", data, 0x98 + 96 + 8, 0x2000, 64)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is True
    assert result.summary["import_directory_present"] is True
    assert result.summary["export_directory_present"] is False


def test_packer_indicators_are_advisory_section_evidence(tmp_path):
    data = _pe_bytes()
    table = 0x98 + 224
    data[table:table + 8] = b"UPX0\x00\x00\x00\x00"
    struct.pack_into("<II", data, table + 8, 0x5000, 0x1000)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is True
    assert "SUSPICIOUS_SECTION_NAME:UPX0" in result.summary["packer_indicators"]
    assert result.summary["scope"] == "headers_and_sections"
