"""
Data models for SecurityScan results and configuration.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from pathlib import Path


class Severity(Enum):
    """Severity levels for security issues."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self):
        return self.value

    @property
    def color(self):
        """Return color code for terminal output."""
        colors = {
            self.CRITICAL: "red",
            self.HIGH: "orange",
            self.MEDIUM: "yellow", 
            self.LOW: "blue",
            self.INFO: "green"
        }
        return colors[self]

    @property
    def numeric_value(self):
        """Return numeric value for sorting."""
        values = {
            self.CRITICAL: 5,
            self.HIGH: 4,
            self.MEDIUM: 3,
            self.LOW: 2,
            self.INFO: 1
        }
        return values[self]


class IssueCategory(Enum):
    """Categories of security issues."""
    DEPENDENCY = "dependency"
    SECRET = "secret"
    SQL_INJECTION = "sql_injection"
    CODE_INJECTION = "code_injection"
    PATH_TRAVERSAL = "path_traversal"
    CRYPTOGRAPHY = "cryptography"
    AUTHENTICATION = "authentication"
    XSS = "xss"
    CONFIGURATION = "configuration"
    FRAMEWORK = "framework"
    GENERAL = "general"

    def __str__(self):
        return self.value


@dataclass
class SecurityIssue:
    """Represents a single security issue found during scanning."""
    
    id: str
    title: str
    description: str
    severity: Severity
    category: IssueCategory
    file_path: Path
    line_number: int
    column_number: int = 0
    code_snippet: str = ""
    fix_suggestion: str = ""
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    confidence: float = 1.0  # 0.0 to 1.0
    rule_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Convert string paths to Path objects."""
        if isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)

    @property
    def is_fixable(self) -> bool:
        """Check if this issue has a suggested fix."""
        return bool(self.fix_suggestion.strip())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "references": self.references,
            "tags": list(self.tags),
            "confidence": self.confidence,
            "rule_id": self.rule_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityIssue":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            severity=Severity(data["severity"]),
            category=IssueCategory(data["category"]),
            file_path=Path(data["file_path"]),
            line_number=data["line_number"],
            column_number=data.get("column_number", 0),
            code_snippet=data.get("code_snippet", ""),
            fix_suggestion=data.get("fix_suggestion", ""),
            cwe_id=data.get("cwe_id"),
            cve_id=data.get("cve_id"),
            references=data.get("references", []),
            tags=set(data.get("tags", [])),
            confidence=data.get("confidence", 1.0),
            rule_id=data.get("rule_id"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ScanStatistics:
    """Statistics about a security scan."""
    
    total_issues: int = 0
    issues_by_severity: Dict[Severity, int] = field(default_factory=dict)
    issues_by_category: Dict[IssueCategory, int] = field(default_factory=dict)
    files_scanned: int = 0
    files_with_issues: int = 0
    scan_duration: float = 0.0
    security_score: float = 0.0
    
    def __post_init__(self):
        """Initialize default values for severity and category counts."""
        for severity in Severity:
            if severity not in self.issues_by_severity:
                self.issues_by_severity[severity] = 0
        
        for category in IssueCategory:
            if category not in self.issues_by_category:
                self.issues_by_category[category] = 0

    def calculate_security_score(self) -> float:
        """Calculate security score based on issues found."""
        if self.total_issues == 0:
            return 100.0
        
        # Weight by severity
        weighted_issues = (
            self.issues_by_severity.get(Severity.CRITICAL, 0) * 10 +
            self.issues_by_severity.get(Severity.HIGH, 0) * 5 +
            self.issues_by_severity.get(Severity.MEDIUM, 0) * 2 +
            self.issues_by_severity.get(Severity.LOW, 0) * 1 +
            self.issues_by_severity.get(Severity.INFO, 0) * 0.5
        )
        
        # Normalize to 0-100 scale
        max_possible_issues = self.files_scanned * 10  # Assume max 10 issues per file
        if max_possible_issues == 0:
            return 100.0
            
        score = max(0, 100 - (weighted_issues / max_possible_issues * 100))
        self.security_score = round(score, 1)
        return self.security_score


@dataclass
class ScanResult:
    """Complete result of a security scan."""
    
    project_path: Path
    issues: List[SecurityIssue] = field(default_factory=list)
    statistics: ScanStatistics = field(default_factory=ScanStatistics)
    scan_timestamp: datetime = field(default_factory=datetime.now)
    scanner_version: str = "1.0.0"
    configuration: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize statistics and update counts."""
        if isinstance(self.project_path, str):
            self.project_path = Path(self.project_path)
        
        # Update statistics
        self.statistics.total_issues = len(self.issues)
        
        for issue in self.issues:
            self.statistics.issues_by_severity[issue.severity] += 1
            self.statistics.issues_by_category[issue.category] += 1
        
        # Calculate security score
        self.statistics.calculate_security_score()
        
        # Count unique files with issues
        files_with_issues = set(issue.file_path for issue in self.issues)
        self.statistics.files_with_issues = len(files_with_issues)

    def get_issues_by_severity(self, severity: Severity) -> List[SecurityIssue]:
        """Get all issues of a specific severity."""
        return [issue for issue in self.issues if issue.severity == severity]

    def get_issues_by_category(self, category: IssueCategory) -> List[SecurityIssue]:
        """Get all issues of a specific category."""
        return [issue for issue in self.issues if issue.category == category]

    def get_issues_by_file(self, file_path: Path) -> List[SecurityIssue]:
        """Get all issues in a specific file."""
        return [issue for issue in self.issues if issue.file_path == file_path]

    def get_critical_issues(self) -> List[SecurityIssue]:
        """Get all critical and high severity issues."""
        return [
            issue for issue in self.issues 
            if issue.severity in [Severity.CRITICAL, Severity.HIGH]
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": str(self.project_path),
            "issues": [issue.to_dict() for issue in self.issues],
            "statistics": {
                "total_issues": self.statistics.total_issues,
                "issues_by_severity": {
                    severity.value: count 
                    for severity, count in self.statistics.issues_by_severity.items()
                },
                "issues_by_category": {
                    category.value: count 
                    for category, count in self.statistics.issues_by_category.items()
                },
                "files_scanned": self.statistics.files_scanned,
                "files_with_issues": self.statistics.files_with_issues,
                "scan_duration": self.statistics.scan_duration,
                "security_score": self.statistics.security_score,
            },
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "scanner_version": self.scanner_version,
            "configuration": self.configuration,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        """Create from dictionary."""
        issues = [SecurityIssue.from_dict(issue_data) for issue_data in data.get("issues", [])]
        
        stats_data = data.get("statistics", {})
        statistics = ScanStatistics(
            total_issues=stats_data.get("total_issues", 0),
            files_scanned=stats_data.get("files_scanned", 0),
            files_with_issues=stats_data.get("files_with_issues", 0),
            scan_duration=stats_data.get("scan_duration", 0.0),
            security_score=stats_data.get("security_score", 0.0),
        )
        
        # Restore severity counts
        severity_data = stats_data.get("issues_by_severity", {})
        for severity_str, count in severity_data.items():
            statistics.issues_by_severity[Severity(severity_str)] = count
        
        # Restore category counts
        category_data = stats_data.get("issues_by_category", {})
        for category_str, count in category_data.items():
            statistics.issues_by_category[IssueCategory(category_str)] = count
        
        return cls(
            project_path=Path(data["project_path"]),
            issues=issues,
            statistics=statistics,
            scan_timestamp=datetime.fromisoformat(data["scan_timestamp"]),
            scanner_version=data.get("scanner_version", "1.0.0"),
            configuration=data.get("configuration", {}),
        )
