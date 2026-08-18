"""ARD Guard public package API."""

from .core import Finding, ScanReport, Severity, scan_document

__all__ = ["Finding", "ScanReport", "Severity", "scan_document"]
__version__ = "0.1.0"
