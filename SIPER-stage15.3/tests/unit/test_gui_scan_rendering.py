"""Exercise real render logic with widget doubles, without opening a window."""

from types import SimpleNamespace

from elliot.gui.view import ElliotView


class Widget:
    def __init__(self):
        self.options = {}
        self.value = None

    def configure(self, **kwargs):
        self.options.update(kwargs)

    def set(self, value):
        self.value = value


def make_view():
    cancelled, animated, texts, charts = [], [], [], []
    view = SimpleNamespace(
        COLORS=ElliotView.COLORS, _risk_animation_job="previous-animation",
        _risk_value=76.0, _risk_target=80.0, after_cancel=cancelled.append,
        risk_number_label=Widget(), risk_progress=Widget(), risk_context_label=Widget(),
        _animate_risk_to=animated.append, _draw_entropy=lambda *args: charts.append(args),
        _replace_text=lambda widget, text: texts.append(text), analysis_text=Widget(), tabs=Widget(),
    )
    return view, cancelled, animated, texts, charts


def test_inconclusive_scan_cancels_stale_animation_and_displays_na():
    view, cancelled, animated, texts, _ = make_view()
    ElliotView.render_scan_result(view, {
        "filepath": "locked.exe", "status": "ERROR", "assessment": "INCONCLUSIVE",
        "enforced_action": "NONE", "recommended_decision": "INCONCLUSIVE",
        "pre_execution_scoring": {"score": None}, "reasons": ["FILE_READ_FAILED"],
    })
    assert cancelled == ["previous-animation"]
    assert view._risk_animation_job is None
    assert view.risk_number_label.options == {"text": "N/A", "text_color": ElliotView.COLORS["muted"]}
    assert view.risk_progress.value == 0
    assert not animated
    assert "Assessment: INCONCLUSIVE" in texts[0]
    assert "Enforced action: NONE" in texts[0]
    assert "FILE_READ_FAILED" in texts[0]


def test_complete_pe_scan_renders_scope_without_claiming_signature_trust():
    view, cancelled, animated, texts, charts = make_view()
    ElliotView.render_scan_result(view, {
        "filepath": "fixture.exe", "status": "OK", "assessment": "NO_HIGH_RISK_INDICATORS",
        "pre_execution_scoring": {"score": 0, "decision": "ALLOW"}, "enforced_action": "NONE",
        "pe_summary": {"status": "COMPLETE", "format": "PE32+", "architecture": "x64",
                       "section_count": 1, "is_dll": False, "certificate_table_present": True,
                       "signature_verification": "NOT_PERFORMED"},
        "pe_anomalies": ["PE_WRITABLE_EXECUTABLE_SECTION:0"],
        "block_entropies": [{"index": 0, "entropy": 1.25}],
    })
    assert animated == [0]
    assert not cancelled
    assert charts == [([0], [1.25])]
    assert "headers and sections only" in texts[0]
    assert "Signature verification: NOT_PERFORMED" in texts[0]
    assert "not a malware probability" in texts[0]
    assert "PE_WRITABLE_EXECUTABLE_SECTION:0" in texts[0]
    assert "Policy recommendation: ALLOW" in texts[0]
