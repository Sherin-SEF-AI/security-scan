"""
SecurityScan - Comprehensive security analysis for Python projects.

A powerful security scanning tool that detects vulnerabilities, hardcoded secrets,
and security misconfigurations in Python projects with a single command.
"""

__version__ = "1.0.0"
__author__ = "Sherin Joseph Roy"
__email__ = "sherin.joseph2217@gmail.com"
__description__ = "Comprehensive security analysis for Python projects"

from .core import SecurityScanner
from .models import SecurityIssue, ScanResult, Severity

__all__ = [
    "SecurityScanner",
    "SecurityIssue", 
    "ScanResult",
    "Severity",
    "__version__",
    "__author__",
    "__email__",
    "__description__",
]
