from __future__ import annotations

from concurrent.futures import Executor, Future

from elyra.gui.controller import PardusController


class ImmediateExecutor(Executor):
    def submit(self, fn, /, *args, **kwargs):
        future = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except Exception as exc:
            future.set_exception(exc)
        return future


class FakeModel:
    def __init__(self):
        self.restore_ids = []
        self.scan_paths = []

    def fetch_dashboard(self):
        return {"connected": True, "status": {}, "events": [], "quarantine": [], "policy": {}, "errors": []}

    def scan_file(self, path):
        self.scan_paths.append(path)
        return {"ok": True, "result": {"filepath": path}}

    def restore_file(self, quarantine_id):
        self.restore_ids.append(quarantine_id)
        return {"ok": True, "result": {"quarantine_id": quarantine_id}}


class FakeView:
    def __init__(self):
        self.callbacks = {}
        self.dashboard = None
        self.scan = None
        self.restore = None
        self.errors = []
        self.busy = []
        self.closed = False
        self.scheduled = []

    def bind_actions(self, **callbacks):
        self.callbacks = callbacks

    def schedule(self, delay_ms, callback):
        self.scheduled.append((delay_ms, callback))

    def dispatch(self, callback):
        callback()

    def render_dashboard(self, snapshot):
        self.dashboard = snapshot

    def render_scan_result(self, result):
        self.scan = result

    def render_restore_result(self, result):
        self.restore = result

    def show_error(self, title, message):
        self.errors.append((title, message))

    def set_busy(self, busy, message=""):
        self.busy.append((busy, message))

    def close(self):
        self.closed = True

    def mainloop(self):
        return None


def make_controller():
    model = FakeModel()
    view = FakeView()
    controller = PardusController(model, view, executor=ImmediateExecutor())
    return controller, model, view


def test_controller_refreshes_dashboard() -> None:
    controller, _, view = make_controller()
    controller.refresh_dashboard()
    assert view.dashboard["connected"] is True
    assert view.busy[-1][0] is False


def test_controller_scan_renders_result() -> None:
    controller, model, view = make_controller()
    controller.scan_file("/tmp/a")
    assert model.scan_paths == ["/tmp/a"]
    assert view.scan["filepath"] == "/tmp/a"


def test_controller_restore_requires_selection() -> None:
    controller, _, view = make_controller()
    controller.restore_file("")
    assert view.errors[0][0] == "Restore unavailable"


def test_controller_restore_calls_model() -> None:
    controller, model, view = make_controller()
    controller.restore_file("abc")
    assert model.restore_ids == ["abc"]
    assert view.restore["quarantine_id"] == "abc"


def test_controller_shows_scan_remote_error() -> None:
    controller, model, view = make_controller()
    model.scan_file = lambda path: {"ok": False, "error": {"code": "DENIED", "message": "x"}}
    controller.scan_file("/tmp/a")
    assert "DENIED" in view.errors[0][1]


def test_controller_run_binds_all_actions() -> None:
    controller, _, view = make_controller()
    controller.run()
    assert set(view.callbacks) == {
        "on_refresh",
        "on_scan",
        "on_refresh_quarantine",
        "on_restore",
        "on_close",
    }
    assert view.scheduled[0][0] == 3000


def test_controller_close_is_idempotent() -> None:
    controller, _, view = make_controller()
    controller.close()
    controller.close()
    assert view.closed is True
