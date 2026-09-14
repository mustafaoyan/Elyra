"""On-device ML foundations; no cloud inference."""

from .features import FeatureVector, features_from_scan
from .model import ModelUnavailable, OnDeviceModel

__all__ = ["FeatureVector", "features_from_scan", "ModelUnavailable", "OnDeviceModel"]
