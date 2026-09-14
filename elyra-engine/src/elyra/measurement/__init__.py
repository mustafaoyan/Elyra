"""Leakage-aware local evaluation metrics."""

from .metrics import EvaluationRecord, evaluate_records
from .dataset import DatasetManifestError, manifest_digest, validate_manifest
from .calibration import CalibrationRecord, calibrate_deny_threshold
from .report import build_evaluation_report

__all__ = ["EvaluationRecord", "evaluate_records", "DatasetManifestError", "manifest_digest", "validate_manifest", "CalibrationRecord", "calibrate_deny_threshold", "build_evaluation_report"]
