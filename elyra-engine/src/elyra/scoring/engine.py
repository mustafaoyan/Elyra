"""Deterministic, explainable pre-execution scoring for ELYRA.

The default rule weights and thresholds are development values labelled
PROVISIONAL_NOT_CALIBRATED.  The engine combines evidence extracted by the
canonical static analyser; it does not diagnose malware.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

from elyra.analyzer.static_analyzer import StaticScanResult

_ALLOWED_CATEGORIES = ("entropy", "static", "context")
_CATEGORY_ORDER = {name: index for index, name in enumerate(_ALLOWED_CATEGORIES)}


class InvalidScoringConfiguration(ValueError):
    """Raised when a scoring policy is incomplete or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class RuleSpec:
    rule: str
    category: str
    weight: int
    description: str
    threshold: float | None = None


@dataclass(frozen=True, slots=True)
class ScoringPolicy:
    schema_version: str
    policy_name: str
    policy_status: str
    score_minimum: int
    score_maximum: int
    category_caps: Mapping[str, int]
    decision_thresholds: Mapping[str, int]
    rules: Mapping[str, RuleSpec]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ScoringPolicy":
        try:
            raw_rules = data["rules"]
            rules = {
                str(rule_id): RuleSpec(
                    rule=str(rule_id),
                    category=str(spec["category"]),
                    weight=int(spec["weight"]),
                    description=str(spec["description"]),
                    threshold=(
                        float(spec["threshold"])
                        if "threshold" in spec
                        else None
                    ),
                )
                for rule_id, spec in raw_rules.items()
            }
            policy = cls(
                schema_version=str(data["schema_version"]),
                policy_name=str(data["policy_name"]),
                policy_status=str(data["policy_status"]),
                score_minimum=int(data["score_minimum"]),
                score_maximum=int(data["score_maximum"]),
                category_caps={
                    str(key): int(value)
                    for key, value in data["category_caps"].items()
                },
                decision_thresholds={
                    str(key): int(value)
                    for key, value in data["decision_thresholds"].items()
                },
                rules=rules,
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise InvalidScoringConfiguration(
                f"invalid scoring configuration: {exc}"
            ) from exc
        policy.validate()
        return policy

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ScoringPolicy":
        if path is None:
            resource = files("elyra.config").joinpath("scoring.default.json")
            text = resource.read_text(encoding="utf-8")
        else:
            text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InvalidScoringConfiguration(
                f"scoring configuration is not valid JSON: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise InvalidScoringConfiguration(
                "scoring configuration root must be a JSON object"
            )
        return cls.from_mapping(data)

    def validate(self) -> None:
        if self.policy_status != "PROVISIONAL_NOT_CALIBRATED":
            raise InvalidScoringConfiguration(
                "Stage 4 policy must be labelled PROVISIONAL_NOT_CALIBRATED"
            )
        if self.score_minimum != 0 or self.score_maximum != 100:
            raise InvalidScoringConfiguration("score range must be 0..100")
        if set(self.category_caps) != set(_ALLOWED_CATEGORIES):
            raise InvalidScoringConfiguration(
                "category caps must define entropy, static and context"
            )
        if any(cap < 0 or cap > self.score_maximum for cap in self.category_caps.values()):
            raise InvalidScoringConfiguration("category caps must be within 0..100")

        required_thresholds = {
            "allow_monitor_min",
            "warn_min",
            "deny_min",
            "deny_min_static_score",
        }
        if set(self.decision_thresholds) != required_thresholds:
            raise InvalidScoringConfiguration(
                "decision thresholds must define allow_monitor_min, warn_min, "
                "deny_min and deny_min_static_score"
            )
        allow_monitor = self.decision_thresholds["allow_monitor_min"]
        warn = self.decision_thresholds["warn_min"]
        deny = self.decision_thresholds["deny_min"]
        deny_static = self.decision_thresholds["deny_min_static_score"]
        if not (0 < allow_monitor < warn < deny <= self.score_maximum):
            raise InvalidScoringConfiguration(
                "decision thresholds must increase within the 0..100 score range"
            )
        if not 0 <= deny_static <= self.category_caps["static"]:
            raise InvalidScoringConfiguration(
                "deny_min_static_score must fit within the static category cap"
            )

        for rule_id, rule in self.rules.items():
            if rule.rule != rule_id:
                raise InvalidScoringConfiguration(
                    f"rule key and embedded rule name differ: {rule_id}"
                )
            if rule.category not in _ALLOWED_CATEGORIES:
                raise InvalidScoringConfiguration(
                    f"unsupported rule category for {rule_id}: {rule.category}"
                )
            if rule.weight < 0 or rule.weight > self.score_maximum:
                raise InvalidScoringConfiguration(
                    f"rule weight outside 0..100 for {rule_id}"
                )
            if not rule.description.strip():
                raise InvalidScoringConfiguration(
                    f"rule description is empty for {rule_id}"
                )


@dataclass(frozen=True, slots=True)
class ScoreIndicator:
    rule: str
    category: str
    weight: int
    evidence: Any
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScoringResult:
    score: int
    decision: str
    indicators: list[ScoreIndicator]
    category_scores: dict[str, int]
    raw_category_scores: dict[str, int]
    category_caps: dict[str, int]
    policy_name: str
    policy_status: str
    schema_version: str
    decision_thresholds: dict[str, int]
    scoring_status: str = "OK"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        indicator_dicts = [indicator.to_dict() for indicator in self.indicators]
        return {
            "schema_version": self.schema_version,
            "policy_name": self.policy_name,
            "policy_status": self.policy_status,
            "scoring_status": self.scoring_status,
            "score": self.score,
            "risk_score": f"{self.score}/100",
            "score_is_probability": False,
            "decision": self.decision,
            "category_scores": dict(self.category_scores),
            "raw_category_scores": dict(self.raw_category_scores),
            "category_caps": dict(self.category_caps),
            "decision_thresholds": dict(self.decision_thresholds),
            "indicators": indicator_dicts,
            "contributing_indicators": [item["rule"] for item in indicator_dicts],
            "notes": list(self.notes),
        }


class PreExecutionScoringEngine:
    """Evaluate static evidence with deterministic, visible rule contributions."""

    def __init__(self, policy: ScoringPolicy | None = None) -> None:
        self.policy = policy or ScoringPolicy.load()

    @classmethod
    def from_config_file(cls, path: str | Path) -> "PreExecutionScoringEngine":
        return cls(ScoringPolicy.load(path))

    def _indicator(self, rule_id: str, evidence: Any) -> ScoreIndicator:
        try:
            rule = self.policy.rules[rule_id]
        except KeyError as exc:
            raise InvalidScoringConfiguration(
                f"required scoring rule is missing: {rule_id}"
            ) from exc
        return ScoreIndicator(
            rule=rule.rule,
            category=rule.category,
            weight=rule.weight,
            evidence=evidence,
            description=rule.description,
        )

    def _threshold(self, rule_id: str) -> float:
        rule = self.policy.rules.get(rule_id)
        if rule is None or rule.threshold is None:
            raise InvalidScoringConfiguration(
                f"rule requires a numeric threshold: {rule_id}"
            )
        return rule.threshold

    @staticmethod
    def _has_exact(values: list[str], expected: str) -> bool:
        return expected in values

    @staticmethod
    def _matching_prefix(values: list[str], prefix: str) -> list[str]:
        return sorted(value for value in values if value.startswith(prefix))

    def _collect_entropy(self, scan: StaticScanResult) -> list[ScoreIndicator]:
        indicators: list[ScoreIndicator] = []
        whole_entropy = float(scan.entropy_summary.get("whole_file_entropy", 0.0))
        high_ratio = float(
            scan.entropy_summary.get("high_entropy_block_ratio", 0.0)
        )
        if whole_entropy >= self._threshold("HIGH_WHOLE_FILE_ENTROPY"):
            indicators.append(
                self._indicator("HIGH_WHOLE_FILE_ENTROPY", whole_entropy)
            )
        if high_ratio >= self._threshold("HIGH_ENTROPY_BLOCK_RATIO"):
            indicators.append(
                self._indicator("HIGH_ENTROPY_BLOCK_RATIO", high_ratio)
            )
        return indicators

    def _collect_static(self, scan: StaticScanResult) -> list[ScoreIndicator]:
        indicators: list[ScoreIndicator] = []
        if scan.mime_extension_consistency == "INCONSISTENT":
            indicators.append(
                self._indicator(
                    "MIME_EXTENSION_INCONSISTENT",
                    {
                        "detected_mime": scan.mime_type,
                        "extension": scan.extension,
                        "expected_mime_types": list(scan.expected_mime_types),
                    },
                )
            )

        error_codes = sorted(
            str(error.get("code", "")) for error in scan.errors
        )
        if "MALFORMED_ELF" in error_codes:
            indicators.append(
                self._indicator("MALFORMED_ELF", "MALFORMED_ELF")
            )

        wx_sections = self._matching_prefix(
            scan.elf_anomalies, "WRITABLE_EXECUTABLE_SECTION:"
        )
        if wx_sections:
            indicators.append(
                self._indicator("WRITABLE_EXECUTABLE_SECTION", wx_sections)
            )
        wx_segments = self._matching_prefix(
            scan.elf_anomalies, "WRITABLE_EXECUTABLE_SEGMENT:"
        )
        if wx_segments:
            indicators.append(
                self._indicator("WRITABLE_EXECUTABLE_SEGMENT", wx_segments)
            )
        for rule_id in ("ELF_ENTRY_POINT_ZERO", "ELF_NO_SECTION_HEADERS"):
            if self._has_exact(scan.elf_anomalies, rule_id):
                indicators.append(self._indicator(rule_id, rule_id))

        for rule_id in ("SUID_BIT_SET", "SGID_BIT_SET"):
            if self._has_exact(scan.permission_anomalies, rule_id):
                indicators.append(self._indicator(rule_id, rule_id))

        if self._has_exact(
            scan.permission_anomalies, "WORLD_WRITABLE_AND_EXECUTABLE"
        ):
            indicators.append(
                self._indicator(
                    "WORLD_WRITABLE_AND_EXECUTABLE",
                    scan.permission_details.get("mode_octal"),
                )
            )
        elif self._has_exact(scan.permission_anomalies, "WORLD_WRITABLE"):
            indicators.append(
                self._indicator(
                    "WORLD_WRITABLE", scan.permission_details.get("mode_octal")
                )
            )
        return indicators

    def _collect_context(self, scan: StaticScanResult) -> list[ScoreIndicator]:
        indicators: list[ScoreIndicator] = []
        for rule_id in (
            "TEMPORARY_DIRECTORY",
            "DOWNLOAD_DIRECTORY",
            "REMOVABLE_OR_MOUNTED_MEDIA",
            "HIDDEN_PATH_COMPONENT",
        ):
            if self._has_exact(scan.path_indicators, rule_id):
                indicators.append(
                    self._indicator(
                        rule_id,
                        scan.path_context.get("absolute_path", scan.filepath),
                    )
                )
        return indicators

    def _decision(self, score: int, static_score: int) -> tuple[str, list[str]]:
        thresholds = self.policy.decision_thresholds
        notes: list[str] = []
        if score >= thresholds["deny_min"]:
            if static_score >= thresholds["deny_min_static_score"]:
                return "DENY", notes
            notes.append(
                "DENY_GATE_NOT_MET: static evidence is below the provisional "
                "minimum required for denial"
            )
            return "WARN", notes
        if score >= thresholds["warn_min"]:
            return "WARN", notes
        if score >= thresholds["allow_monitor_min"]:
            return "ALLOW_MONITOR", notes
        return "ALLOW", notes

    def degraded_result(self, rule: str, evidence: Any) -> ScoringResult:
        indicator = ScoreIndicator(
            rule=rule,
            category="system",
            weight=0,
            evidence=evidence,
            description=(
                "Analysis could not be completed; the provisional fail-open policy "
                "allows execution only with monitoring and critical logging."
            ),
        )
        empty_scores = {category: 0 for category in _ALLOWED_CATEGORIES}
        return ScoringResult(
            score=0,
            decision="ALLOW_MONITOR",
            indicators=[indicator],
            category_scores=empty_scores,
            raw_category_scores=dict(empty_scores),
            category_caps=dict(self.policy.category_caps),
            policy_name=self.policy.policy_name,
            policy_status=self.policy.policy_status,
            schema_version=self.policy.schema_version,
            decision_thresholds=dict(self.policy.decision_thresholds),
            scoring_status="DEGRADED",
            notes=["FAIL_OPEN_REQUIRES_CRITICAL_AUDIT_RECORD"],
        )

    def score(self, scan: StaticScanResult) -> ScoringResult:
        if scan.status == "ERROR":
            error_codes = [str(item.get("code", "UNKNOWN")) for item in scan.errors]
            return self.degraded_result("STATIC_ANALYSIS_INCOMPLETE", error_codes)

        indicators = (
            self._collect_entropy(scan)
            + self._collect_static(scan)
            + self._collect_context(scan)
        )
        indicators.sort(
            key=lambda item: (_CATEGORY_ORDER[item.category], item.rule)
        )

        raw_scores = {category: 0 for category in _ALLOWED_CATEGORIES}
        for indicator in indicators:
            raw_scores[indicator.category] += indicator.weight
        category_scores = {
            category: min(raw_scores[category], self.policy.category_caps[category])
            for category in _ALLOWED_CATEGORIES
        }
        score = min(
            self.policy.score_maximum,
            max(self.policy.score_minimum, sum(category_scores.values())),
        )
        decision, notes = self._decision(score, category_scores["static"])
        if scan.status == "PARTIAL":
            notes.append(
                "PARTIAL_STATIC_ANALYSIS: the decision uses the evidence that was available"
            )
        if category_scores["entropy"] > 0 and not (
            category_scores["static"] or category_scores["context"]
        ):
            notes.append(
                "ENTROPY_ONLY_EVIDENCE: entropy is not proof of malware and cannot "
                "satisfy the denial gate by itself"
            )

        return ScoringResult(
            score=score,
            decision=decision,
            indicators=indicators,
            category_scores=category_scores,
            raw_category_scores=raw_scores,
            category_caps=dict(self.policy.category_caps),
            policy_name=self.policy.policy_name,
            policy_status=self.policy.policy_status,
            schema_version=self.policy.schema_version,
            decision_thresholds=dict(self.policy.decision_thresholds),
            notes=notes,
        )
