"""XSS vulnerability scanner."""

from pathlib import Path
from typing import List

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory


class XSSScanner(BaseScanner):
    """Scanner for XSS vulnerabilities."""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "xss"
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan file for XSS vulnerabilities."""
        if self.should_skip_file(file_path):
            return []
        
        content = self.read_file_content(file_path)
        if not content:
            return []
        
        issues = []
        
        # Check for unescaped user input in templates
        issues.extend(self._check_unescaped_input(content, file_path))
        
        return issues
    
    def _check_unescaped_input(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check for unescaped user input."""
        issues = []
        
        # Simple check for potential XSS patterns
        if 'innerHTML' in content or 'dangerouslySetInnerHTML' in content:
            line_number = content.find('innerHTML') + 1
            if line_number == 0:
                line_number = content.find('dangerouslySetInnerHTML') + 1
            line_number = content[:line_number].count('\n') + 1
            
            issue = SecurityIssue(
                id=f"xss_innerhtml_{line_number}",
                title="Potential XSS vulnerability",
                description="Use of innerHTML or dangerouslySetInnerHTML can lead to XSS attacks.",
                severity=Severity.MEDIUM,
                category=IssueCategory.XSS,
                file_path=file_path,
                line_number=line_number,
                fix_suggestion="Use textContent or properly escape HTML content",
                tags={"xss", "innerHTML", "dangerous"},
                confidence=0.7,
                rule_id="xss.innerHTML"
            )
            issues.append(issue)
        
        return issues
