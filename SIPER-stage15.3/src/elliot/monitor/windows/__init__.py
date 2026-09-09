"""Windows local-monitoring implementation for ELLIOT.

The package is import-safe on Linux/macOS CI.  Runtime activation is limited to
Windows and always defaults to local, monitor-only operation.
"""

from .backends import AutoWindowsBackend, EtwBackend, ReadDirectoryChangesBackend
from .controller import WindowsMonitorController
from .entropy import WindowsEntropyAnalyzer, WindowsEntropyResult, filesystem_type
from .events import WindowsMonitorEvent, WindowsMonitorRecord
from .policy import WindowsMonitorPolicy

__all__ = [
    "AutoWindowsBackend",
    "EtwBackend",
    "ReadDirectoryChangesBackend",
    "WindowsMonitorController",
    "WindowsEntropyAnalyzer",
    "WindowsEntropyResult",
    "WindowsMonitorEvent",
    "WindowsMonitorRecord",
    "WindowsMonitorPolicy",
    "filesystem_type",
]
