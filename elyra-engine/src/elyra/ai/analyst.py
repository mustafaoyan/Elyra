"""Bounded local evidence interpreter; it never executes or fetches files."""

from __future__ import annotations

from typing import Any, Mapping

_INJECTION_MARKERS = ("ignore previous", "system prompt", "developer message", "jailbreak", "override instructions")
_MAX_INDICATORS = 32
_MAX_TEXT = 512


class EvidenceAnalyst:
    """Summarise scanner evidence into a review recommendation only."""

    def analyze(self, evidence: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(evidence, Mapping):
            raise TypeError("evidence must be a mapping")
        indicators = evidence.get("indicators") or []
        notes = evidence.get("notes") or []
        if not isinstance(indicators, list) or not isinstance(notes, list) or len(indicators) > _MAX_INDICATORS or len(notes) > _MAX_INDICATORS:
            return self._inconclusive("evidence_budget_exceeded")
        text_values: list[str] = []
        for item in [*indicators, *notes]:
            if isinstance(item, Mapping):
                value = str(item.get("rule", "")) + " " + str(item.get("description", ""))
            else:
                value = str(item)
            if len(value) > _MAX_TEXT:
                return self._inconclusive("evidence_field_too_large")
            text_values.append(value)
        joined = " ".join(text_values).lower()
        if any(marker in joined for marker in _INJECTION_MARKERS):
            return self._inconclusive("untrusted_instruction_like_text")
        score = evidence.get("score")
        decision = str(evidence.get("decision", "INCONCLUSIVE"))
        if not isinstance(score, (int, float)) or not 0 <= float(score) <= 100:
            return self._inconclusive("missing_or_invalid_score")
        reasons = [value for value in text_values if value.strip()][:8]
        if decision == "DENY" or float(score) >= 80:
            band, recommendation = "HIGH", "REVIEW_REQUIRED"
        elif decision == "WARN" or float(score) >= 50:
            band, recommendation = "MEDIUM", "REVIEW_RECOMMENDED"
        elif decision == "ALLOW_MONITOR" or float(score) >= 25:
            band, recommendation = "LOW", "MONITOR"
        else:
            band, recommendation = "MINIMAL", "NO_ADDITIONAL_ACTION"
        return {"schema_version": "elyra.ai.analysis.v1", "status": "OK", "risk_band": band, "summary": f"Static evidence produced score {float(score):.2f}/100 with decision {decision}.", "reasons": reasons, "recommendation": recommendation, "authoritative": False, "actions_allowed": []}

    @staticmethod
    def _inconclusive(reason: str) -> dict[str, Any]:
        return {"schema_version": "elyra.ai.analysis.v1", "status": "INCONCLUSIVE", "risk_band": "UNKNOWN", "summary": "Evidence could not be safely interpreted.", "reasons": [reason], "recommendation": "REVIEW", "authoritative": False, "actions_allowed": []}
