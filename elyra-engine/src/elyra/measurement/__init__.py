"""Leakage-aware local evaluation metrics."""

from .metrics import EvaluationRecord, evaluate_records
from .dataset import DatasetManifestError, manifest_digest, validate_manifest
from .calibration import CalibrationRecord, calibrate_deny_threshold

__all__ = ["EvaluationRecord", "evaluate_records", "DatasetManifestError", "manifest_digest", "validate_manifest", "CalibrationRecord", "calibrate_deny_threshold"]
