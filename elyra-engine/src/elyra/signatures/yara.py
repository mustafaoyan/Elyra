"""Bounded, local-only YARA-X evaluation boundary.

The adapter never downloads rules or executes a sample.  It reports an explicit
unavailable state when the optional ``yara-x`` dependency is not installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

MAX_RULE_BYTES = 1_048_576
MAX_SAMPLE_BYTES = 8 * 1_024 * 1_024


@dataclass(frozen=True)
class YaraEvaluation:
    status: str
    matches: tuple[str, ...] = ()
    error: str | None = None


class _Backend(Protocol):
    def compile(self, source: str) -> Any: ...
    def scan(self, compiled: Any, sample: bytes) -> list[str]: ...


class _YaraXBackend:
    def __init__(self) -> None:
        try:
            import yara_x  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("optional dependency yara-x is not installed") from exc
        self._module = yara_x

    def compile(self, source: str) -> Any:
        compiler = getattr(self._module, "Compiler", None)
        if compiler is not None:
            instance = compiler()
            instance.add_source(source)
            return instance.build()
        compile_fn = getattr(self._module, "compile", None)
        if compile_fn is None:
            raise RuntimeError("unsupported yara-x Python API")
        return compile_fn(source)

    def scan(self, compiled: Any, sample: bytes) -> list[str]:
        scan_fn = getattr(compiled, "scan", None) or getattr(compiled, "scan_bytes", None)
        if scan_fn is None:
            raise RuntimeError("unsupported yara-x scan API")
        result = scan_fn(sample)
        names: list[str] = []
        for match in result or ():
            name = getattr(match, "identifier", None) or getattr(match, "name", None)
            if isinstance(name, str) and name:
                names.append(name)
            elif isinstance(match, str):
                names.append(match)
        return sorted(set(names))


class YaraXEvaluator:
    """Compile and scan one local rule source under strict resource limits."""

    def __init__(self, backend: _Backend | None = None) -> None:
        self._backend = backend
        self._backend_error: str | None = None
        if backend is None:
            try:
                self._backend = _YaraXBackend()
            except RuntimeError as exc:
                self._backend_error = str(exc)

    def evaluate(self, rule_source: str, sample: bytes) -> YaraEvaluation:
        if self._backend is None:
            return YaraEvaluation("UNAVAILABLE_DEPENDENCY", error=self._backend_error)
        if not isinstance(rule_source, str) or not rule_source.strip():
            return YaraEvaluation("INVALID_RULE", error="rule source is empty")
        if len(rule_source.encode("utf-8")) > MAX_RULE_BYTES:
            return YaraEvaluation("RESOURCE_LIMIT", error="rule source exceeds byte budget")
        if not isinstance(sample, bytes):
            return YaraEvaluation("INVALID_SAMPLE", error="sample must be bytes")
        if len(sample) > MAX_SAMPLE_BYTES:
            return YaraEvaluation("RESOURCE_LIMIT", error="sample exceeds byte budget")
        try:
            compiled = self._backend.compile(rule_source)
            matches = self._backend.scan(compiled, sample)
        except Exception as exc:  # backend errors become explicit evidence
            return YaraEvaluation("COMPILE_OR_SCAN_ERROR", error=str(exc))
        return YaraEvaluation("MATCH" if matches else "NO_MATCH", tuple(matches))
