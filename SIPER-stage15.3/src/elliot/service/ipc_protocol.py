"""Versioned JSON protocol for ELLIOT's Unix-domain-socket IPC.

The wire format is UTF-8 JSON, one object per line.  Requests and responses are
bounded in size and validated before privileged code receives them.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PATH_CHARACTERS = 4096
MAX_REQUEST_ID_CHARACTERS = 128
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")


class ProtocolError(ValueError):
    """A client-visible protocol validation failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


@dataclass(frozen=True, slots=True)
class RequestMessage:
    version: int
    request_id: str
    action: str
    params: dict[str, Any]


_ACTION_PARAMS: dict[str, tuple[set[str], set[str]]] = {
    "get_status": (set(), set()),
    "list_events": (set(), {"limit"}),
    "list_runtime_states": (set(), {"limit"}),
    "list_quarantine": (set(), set()),
    "get_policy": (set(), set()),
    "scan_file": ({"path"}, set()),
    "restore_file": ({"quarantine_id"}, {"destination"}),
    "delete_permanently": ({"quarantine_id"}, set()),
    "update_enforcement_policy": ({"mode"}, set()),
}


def new_request_id() -> str:
    return uuid.uuid4().hex


def _require_plain_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError("INVALID_SCHEMA", f"'{field}' must be a JSON object")
    if not all(isinstance(key, str) for key in value):
        raise ProtocolError("INVALID_SCHEMA", f"'{field}' keys must be strings")
    return dict(value)


def _validate_request_id(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError("INVALID_REQUEST_ID", "'request_id' must be a non-empty string")
    if len(value) > MAX_REQUEST_ID_CHARACTERS or not _REQUEST_ID_PATTERN.fullmatch(value):
        raise ProtocolError(
            "INVALID_REQUEST_ID",
            "'request_id' contains unsupported characters or is too long",
        )
    return value


def _require_string(
    params: Mapping[str, Any],
    name: str,
    *,
    allow_none: bool = False,
    max_characters: int | None = None,
) -> str | None:
    value = params.get(name)
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value:
        raise ProtocolError("INVALID_PARAMETERS", f"'{name}' must be a non-empty string")
    if max_characters is not None and len(value) > max_characters:
        raise ProtocolError("INVALID_PARAMETERS", f"'{name}' is too long")
    if "\x00" in value:
        raise ProtocolError("INVALID_PARAMETERS", f"'{name}' contains a NUL character")
    return value


def _validate_quarantine_id(value: str | None) -> str:
    if value is None:
        raise ProtocolError("INVALID_PARAMETERS", "'quarantine_id' is required")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ProtocolError("INVALID_PARAMETERS", "'quarantine_id' must be a UUID") from exc
    canonical = str(parsed)
    if value != canonical:
        raise ProtocolError("INVALID_PARAMETERS", "'quarantine_id' must use canonical UUID form")
    return canonical


def validate_action_params(action: str, params: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize the parameters for one supported action."""

    if action not in _ACTION_PARAMS:
        raise ProtocolError("UNKNOWN_ACTION", f"Unsupported action: {action}")
    required, optional = _ACTION_PARAMS[action]
    keys = set(params)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ProtocolError(
            "INVALID_PARAMETERS",
            f"Missing parameter(s): {', '.join(sorted(missing))}",
        )
    if unknown:
        raise ProtocolError(
            "INVALID_PARAMETERS",
            f"Unknown parameter(s): {', '.join(sorted(unknown))}",
        )

    normalized = dict(params)
    if action in {"list_events", "list_runtime_states"}:
        limit = normalized.get("limit", 50)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ProtocolError("INVALID_PARAMETERS", "'limit' must be an integer from 1 to 200")
        normalized["limit"] = limit
    elif action == "scan_file":
        path = _require_string(normalized, "path", max_characters=MAX_PATH_CHARACTERS)
        if not path.startswith("/"):
            raise ProtocolError("INVALID_PARAMETERS", "'path' must be absolute")
        normalized["path"] = path
    elif action == "restore_file":
        normalized["quarantine_id"] = _validate_quarantine_id(
            _require_string(normalized, "quarantine_id", max_characters=64)
        )
        destination = _require_string(
            normalized,
            "destination",
            allow_none=True,
            max_characters=MAX_PATH_CHARACTERS,
        )
        if destination is not None and not destination.startswith("/"):
            raise ProtocolError("INVALID_PARAMETERS", "'destination' must be absolute")
        normalized["destination"] = destination
    elif action == "delete_permanently":
        normalized["quarantine_id"] = _validate_quarantine_id(
            _require_string(normalized, "quarantine_id", max_characters=64)
        )
    elif action == "update_enforcement_policy":
        mode = _require_string(normalized, "mode", max_characters=32)
        if mode not in {"MONITOR_ONLY", "ENFORCEMENT"}:
            raise ProtocolError(
                "INVALID_PARAMETERS",
                "'mode' must be MONITOR_ONLY or ENFORCEMENT",
            )
        normalized["mode"] = mode
    return normalized


def validate_request_object(value: Any) -> RequestMessage:
    request = _require_plain_object(value, "request")
    allowed_fields = {"version", "request_id", "action", "params"}
    unknown = set(request) - allowed_fields
    missing = {"version", "request_id", "action", "params"} - set(request)
    if missing:
        raise ProtocolError(
            "INVALID_SCHEMA", f"Missing field(s): {', '.join(sorted(missing))}"
        )
    if unknown:
        raise ProtocolError(
            "INVALID_SCHEMA", f"Unknown field(s): {', '.join(sorted(unknown))}"
        )

    request_id = _validate_request_id(request["request_id"])
    if request["version"] != PROTOCOL_VERSION:
        raise ProtocolError(
            "UNSUPPORTED_VERSION",
            f"Protocol version {PROTOCOL_VERSION} is required",
            request_id=request_id,
        )
    action = request["action"]
    if not isinstance(action, str) or not action:
        raise ProtocolError(
            "INVALID_SCHEMA", "'action' must be a non-empty string", request_id=request_id
        )
    params = _require_plain_object(request["params"], "params")
    try:
        params = validate_action_params(action, params)
    except ProtocolError as exc:
        exc.request_id = request_id
        raise
    return RequestMessage(
        version=PROTOCOL_VERSION,
        request_id=request_id,
        action=action,
        params=params,
    )


def decode_request_line(line: bytes) -> RequestMessage:
    if not line:
        raise ProtocolError("EMPTY_MESSAGE", "Request line is empty")
    if len(line) > MAX_REQUEST_BYTES:
        raise ProtocolError("MESSAGE_TOO_LARGE", "Request exceeds the size limit")
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("INVALID_UTF8", "Request is not valid UTF-8") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("INVALID_JSON", "Request is not valid JSON") from exc
    return validate_request_object(value)


def build_request(action: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
    request = {
        "version": PROTOCOL_VERSION,
        "request_id": new_request_id(),
        "action": action,
        "params": dict(params or {}),
    }
    validated = validate_request_object(request)
    return {
        "version": validated.version,
        "request_id": validated.request_id,
        "action": validated.action,
        "params": validated.params,
    }


def success_response(request_id: str, result: Any) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": True,
        "result": result,
    }


def error_response(
    request_id: str | None,
    code: str,
    message: str,
) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": False,
        "error": {"code": code, "message": message},
    }


def encode_json_line(value: Any, *, maximum: int) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise ProtocolError("SERIALIZATION_FAILED", "Response is not JSON serializable") from exc
    if len(encoded) > maximum:
        raise ProtocolError("MESSAGE_TOO_LARGE", "Encoded message exceeds the size limit")
    return encoded
