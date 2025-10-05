"""Authentication security scanner."""

from pathlib import Path
from typing import List

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory


class AuthenticationScanner(BaseScanner):
    """Scanner for authentication-related security issues."""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "authentication"
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan file for authentication security issues."""
        if self.should_skip_file(file_path) or not self.is_python_file(file_path):
            return []
        
        content = self.read_file_content(file_path)
        if not content:
            return []
        
        issues = []
        
        # Check for missing authentication
        issues.extend(self._check_missing_authentication(content, file_path))
        
        # Check for weak password policies
        issues.extend(self._check_weak_password_policies(content, file_path))
        
        return issues
    
    def _check_missing_authentication(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check for missing authentication."""
        issues = []
        
        # This is a simplified check - in reality, you'd want more sophisticated detection
        if 'login' in content.lower() and 'password' in content.lower():
            # Check if there's actual authentication logic
            auth_indicators = ['authenticate', 'login', 'verify', 'check_password']
            if not any(indicator in content.lower() for indicator in auth_indicators):
                issue = SecurityIssue(
                    id=f"missing_auth_{1}",
                    title="Potential missing authentication",
                    description="Code references login/password but may be missing proper authentication logic.",
                    severity=Severity.MEDIUM,
                    category=IssueCategory.AUTHENTICATION,
                    file_path=file_path,
                    line_number=1,
                    fix_suggestion="Implement proper authentication and authorization checks",
                    tags={"authentication", "missing_auth"},
                    confidence=0.5,
                    rule_id="authentication.missing_auth"
                )
                issues.append(issue)
        
        return issues
    
    def _check_weak_password_policies(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check for weak password policies."""
        issues = []
        
        # Check for simple password validation
        if len(content) < 10:  # Very simple check for minimum password length
            if 'password' in content.lower() and 'len' not in content.lower():
                issue = SecurityIssue(
                    id=f"weak_password_policy_{1}",
                    title="Weak password policy",
                    description="Password validation may be missing minimum length requirements.",
                    severity=Severity.LOW,
                    category=IssueCategory.AUTHENTICATION,
                    file_path=file_path,
                    line_number=1,
                    fix_suggestion="Implement strong password policies with minimum length and complexity requirements",
                    tags={"authentication", "password_policy"},
                    confidence=0.3,
                    rule_id="authentication.weak_password_policy"
                )
                issues.append(issue)
        
        return issues
