"""
Framework-specific security scanner.
"""

from pathlib import Path
from typing import List

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory


class FrameworkScanner(BaseScanner):
    """Scanner for framework-specific security issues."""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "framework"
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan file for framework-specific security issues."""
        if self.should_skip_file(file_path):
            return []
        
        content = self.read_file_content(file_path)
        if not content:
            return []
        
        issues = []
        
        # Django-specific checks
        if 'django' in content.lower() or file_path.name in ['settings.py', 'manage.py']:
            issues.extend(self._check_django_security(content, file_path))
        
        # Flask-specific checks
        if 'flask' in content.lower() or 'app.py' in file_path.name:
            issues.extend(self._check_flask_security(content, file_path))
        
        # FastAPI-specific checks
        if 'fastapi' in content.lower() or 'main.py' in file_path.name:
            issues.extend(self._check_fastapi_security(content, file_path))
        
        return issues
    
    def _check_django_security(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check Django-specific security issues."""
        issues = []
        
        # Check for DEBUG = True
        if 'DEBUG = True' in content or 'DEBUG=True' in content:
            line_number = content.find('DEBUG = True') + 1
            if line_number == 0:
                line_number = content.find('DEBUG=True') + 1
            line_number = content[:line_number].count('\n') + 1
            
            issue = SecurityIssue(
                id=f"django_debug_{line_number}",
                title="Django DEBUG mode enabled",
                description="DEBUG mode is enabled in Django settings. This exposes sensitive information.",
                severity=Severity.HIGH,
                category=IssueCategory.FRAMEWORK,
                file_path=file_path,
                line_number=line_number,
                fix_suggestion="Set DEBUG = False in production",
                tags={"django", "debug", "configuration"},
                confidence=0.9,
                rule_id="framework.django_debug"
            )
            issues.append(issue)
        
        return issues
    
    def _check_flask_security(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check Flask-specific security issues."""
        issues = []
        
        # Check for debug mode
        if 'app.run(debug=True)' in content:
            line_number = content.find('app.run(debug=True)') + 1
            line_number = content[:line_number].count('\n') + 1
            
            issue = SecurityIssue(
                id=f"flask_debug_{line_number}",
                title="Flask debug mode enabled",
                description="Flask debug mode is enabled. This exposes sensitive information.",
                severity=Severity.HIGH,
                category=IssueCategory.FRAMEWORK,
                file_path=file_path,
                line_number=line_number,
                fix_suggestion="Set debug=False in production",
                tags={"flask", "debug", "configuration"},
                confidence=0.9,
                rule_id="framework.flask_debug"
            )
            issues.append(issue)
        
        return issues
    
    def _check_fastapi_security(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check FastAPI-specific security issues."""
        issues = []
        
        # Check for missing CORS configuration
        if 'FastAPI' in content and 'CORSMiddleware' not in content:
            # This is a simplified check - in reality, you'd want more sophisticated detection
            issue = SecurityIssue(
                id=f"fastapi_cors_{1}",
                title="Missing CORS configuration",
                description="FastAPI application may be missing CORS configuration.",
                severity=Severity.MEDIUM,
                category=IssueCategory.FRAMEWORK,
                file_path=file_path,
                line_number=1,
                fix_suggestion="Configure CORS middleware if needed",
                tags={"fastapi", "cors", "configuration"},
                confidence=0.5,
                rule_id="framework.fastapi_cors"
            )
            issues.append(issue)
        
        return issues
