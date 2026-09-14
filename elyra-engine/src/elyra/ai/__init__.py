"""On-device ML foundations; no cloud inference."""

from .features import FeatureVector, features_from_scan
from .model import ModelUnavailable, OnDeviceModel
from .training import train_linear_baseline
from .evaluation import evaluate_binary_predictions
from .runtime import recommendation_from_model
from .analyst import EvidenceAnalyst

__all__ = ["FeatureVector", "features_from_scan", "ModelUnavailable", "OnDeviceModel", "train_linear_baseline", "evaluate_binary_predictions", "recommendation_from_model", "EvidenceAnalyst"]
