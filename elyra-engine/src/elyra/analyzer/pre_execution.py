"""fanotify-facing adapter for static analysis and Stage 4 scoring."""

from __future__ import annotations

import logging
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from pathlib import Path
from typing import Callable

from elyra.scoring.engine import PreExecutionScoringEngine

from .static_analyzer import StaticFileScanner, StaticScanResult

logger = logging.getLogger("elyra.analyzer.pre_execution")


class PreExecutionAnalyzer:
    """Run static analysis in a dedicated executor with a bounded timeout.

    The event-handler executor and analysis executor are separate, preventing
    the nested-worker starvation present in designs that submit both layers to
    one limited pool.
    """

    def __init__(
        self,
        max_w: int = 4,
        timeout: float = 2.0,
        scoring_engine: PreExecutionScoringEngine | None = None,
        scanner: StaticFileScanner | None = None,
    ) -> None:
        if max_w <= 0:
            raise ValueError("max_w must be greater than zero")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self.pool = ThreadPoolExecutor(
            max_workers=max_w, thread_name_prefix="ElyraAnalysis"
        )
        self.timeout = timeout
        self.scanner = scanner or StaticFileScanner()
        self.scoring_engine = scoring_engine or PreExecutionScoringEngine()

    def close(self) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)

    def _wait(
        self,
        future: Future[dict[str, object]],
        *,
        filepath: str,
        timeout: float | None,
    ) -> dict[str, object]:
        effective_timeout = self.timeout if timeout is None else min(self.timeout, timeout)
        if effective_timeout <= 0:
            future.cancel()
            return self._degraded_timeout(filepath, 0.0)
        try:
            return future.result(timeout=effective_timeout)
        except TimeoutError:
            future.cancel()
            return self._degraded_timeout(filepath, effective_timeout)
        except (OSError, ValueError, RuntimeError) as exc:
            logger.critical(
                "Static analysis failed; fail-open used for %s: %s", filepath, exc
            )
            result = self.scoring_engine.degraded_result(
                "ANALYSIS_ERROR_FAIL_OPEN",
                {"filepath": filepath, "error_type": type(exc).__name__},
            ).to_dict()
            result["error"] = "exception"
            return result

    def _degraded_timeout(self, filepath: str, timeout: float) -> dict[str, object]:
        logger.critical("Static analysis timed out; fail-open used: %s", filepath)
        result = self.scoring_engine.degraded_result(
            "ANALYSIS_TIMEOUT_FAIL_OPEN",
            {"filepath": filepath, "timeout_seconds": timeout},
        ).to_dict()
        result["error"] = "timeout"
        return result

    def analyze_file_async(
        self, filepath: str, *, timeout: float | None = None
    ) -> dict[str, object]:
        future = self.pool.submit(self.analyze_file, filepath)
        return self._wait(future, filepath=filepath, timeout=timeout)

    def analyze_open_fd_async(
        self,
        fd: int,
        original_path: str,
        *,
        timeout: float | None = None,
    ) -> dict[str, object]:
        future = self.pool.submit(self.analyze_open_fd, fd, original_path)
        return self._wait(future, filepath=original_path, timeout=timeout)

    def _score_scan(self, scan: StaticScanResult) -> dict[str, object]:
        result = self.scoring_engine.score(scan).to_dict()
        result["scan_status"] = scan.status
        result["file_size"] = scan.file_size
        result["mime_type"] = scan.mime_type
        result["is_elf"] = scan.is_elf
        result["block_entropies"] = list(scan.block_entropies)
        result["whole_file_entropy"] = scan.entropy_summary.get(
            "whole_file_entropy"
        )
        result["file_identity"] = dict(scan.file_identity)
        result["identity_source"] = scan.identity_source
        if scan.status == "ERROR":
            result["error"] = "scan_error"
        if scan.status == "PARTIAL":
            # An incomplete scan is evidence of uncertainty, never a deny
            # proof. Keep it visible and let the fanotify policy decide the
            # configured fail-open/fail-closed behavior.
            result["decision"] = "ALLOW_MONITOR"
            result["scoring_status"] = "INCONCLUSIVE"
            result.setdefault("notes", []).append("STATIC_SCAN_INCONCLUSIVE")
        return result

    def analyze_file(self, filepath: str) -> dict[str, object]:
        return self._score_scan(self.scanner.scan(Path(filepath)))

    def analyze_open_fd(self, fd: int, original_path: str) -> dict[str, object]:
        return self._score_scan(self.scanner.scan_open_fd(fd, original_path))
