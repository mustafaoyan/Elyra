"""Asynchronous controller connecting the GUI to the official daemon API."""

from __future__ import annotations

import logging
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from typing import Any, Callable, Protocol

logger = logging.getLogger("elliot.gui.controller")


class GuiView(Protocol):
    def bind_actions(
        self,
        *,
        on_refresh: Callable[[], None],
        on_scan: Callable[[str], None],
        on_refresh_quarantine: Callable[[], None],
        on_restore: Callable[[str], None],
        on_close: Callable[[], None],
    ) -> None: ...

    def schedule(self, delay_ms: int, callback: Callable[[], None]) -> Any: ...
    def dispatch(self, callback: Callable[[], None]) -> Any: ...
    def render_dashboard(self, snapshot: dict[str, Any]) -> None: ...
    def render_scan_result(self, result: dict[str, Any]) -> None: ...
    def render_restore_result(self, result: dict[str, Any]) -> None: ...
    def show_error(self, title: str, message: str) -> None: ...
    def set_busy(self, busy: bool, message: str = "") -> None: ...
    def close(self) -> None: ...
    def mainloop(self) -> None: ...


class PardusController:
    def __init__(
        self,
        model: Any,
        view: GuiView,
        *,
        refresh_interval_ms: int = 3000,
        executor: Executor | None = None,
    ) -> None:
        self.model = model
        self.view = view
        self.refresh_interval_ms = refresh_interval_ms
        self.executor = executor or ThreadPoolExecutor(
            max_workers=3,
            thread_name_prefix="elliot-gui",
        )
        self._owns_executor = executor is None
        self._closed = False
        self._refresh_in_flight = False

    def run(self) -> None:
        self.view.bind_actions(
            on_refresh=self.refresh_dashboard,
            on_scan=self.scan_file,
            on_refresh_quarantine=self.refresh_dashboard,
            on_restore=self.restore_file,
            on_close=self.close,
        )
        self.refresh_dashboard()
        self.view.schedule(self.refresh_interval_ms, self._periodic_refresh)
        self.view.mainloop()

    def _periodic_refresh(self) -> None:
        if self._closed:
            return
        self.refresh_dashboard()
        self.view.schedule(self.refresh_interval_ms, self._periodic_refresh)

    def _submit(
        self,
        operation: Callable[[], dict[str, Any]],
        on_success: Callable[[dict[str, Any]], None],
        *,
        busy_message: str,
        on_finally: Callable[[], None] | None = None,
    ) -> None:
        if self._closed:
            return
        self.view.set_busy(True, busy_message)
        future = self.executor.submit(operation)

        def complete(done: Future[dict[str, Any]]) -> None:
            def deliver() -> None:
                try:
                    result = done.result()
                except Exception as exc:  # Unexpected programming/runtime error; never silent.
                    logger.exception("GUI background operation failed")
                    self.view.show_error("ELLIOT operation failed", str(exc))
                else:
                    on_success(result)
                finally:
                    self.view.set_busy(False)
                    if on_finally is not None:
                        on_finally()

            if not self._closed:
                self.view.dispatch(deliver)

        future.add_done_callback(complete)

    def refresh_dashboard(self) -> None:
        if self._closed or self._refresh_in_flight:
            return
        self._refresh_in_flight = True

        def finished() -> None:
            self._refresh_in_flight = False

        self._submit(
            self.model.fetch_dashboard,
            self.view.render_dashboard,
            busy_message="Refreshing daemon data…",
            on_finally=finished,
        )

    def scan_file(self, path: str) -> None:
        if not path:
            return

        def handle(response: dict[str, Any]) -> None:
            if response.get("ok") is True:
                self.view.render_scan_result(response.get("result", {}))
            else:
                error = response.get("error", {})
                self.view.show_error(
                    "Scan failed",
                    f"{error.get('code', 'UNKNOWN')}: {error.get('message', 'Unknown error')}",
                )

        self._submit(
            lambda: self.model.scan_file(path),
            handle,
            busy_message="Analysing selected file…",
        )

    def restore_file(self, quarantine_id: str) -> None:
        if not quarantine_id:
            self.view.show_error("Restore unavailable", "Select a quarantine record first.")
            return

        def handle(response: dict[str, Any]) -> None:
            if response.get("ok") is True:
                self.view.render_restore_result(response.get("result", {}))
                self.refresh_dashboard()
            else:
                error = response.get("error", {})
                self.view.show_error(
                    "Restore denied or failed",
                    f"{error.get('code', 'UNKNOWN')}: {error.get('message', 'Unknown error')}",
                )

        self._submit(
            lambda: self.model.restore_file(quarantine_id),
            handle,
            busy_message="Requesting authorised restoration…",
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._owns_executor:
            self.executor.shutdown(wait=False, cancel_futures=True)
        self.view.close()
