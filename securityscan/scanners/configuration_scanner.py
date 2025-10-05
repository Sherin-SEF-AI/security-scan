"""Configuration security scanner."""

from pathlib import Path
from typing import List

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory


class ConfigurationScanner(BaseScanner):
    """Scanner for configuration-related security issues."""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "configuration"
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan file for configuration security issues."""
        if self.should_skip_file(file_path):
            return []
        
        content = self.read_file_content(file_path)
        if not content:
            return []
        
        issues = []
        
        # Check for insecure configurations
        issues.extend(self._check_insecure_configurations(content, file_path))
        
        return issues
    
    def _check_insecure_configurations(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check for insecure configurations."""
        issues = []
        
        # Check for insecure default configurations
        insecure_configs = {
            'ALLOWED_HOSTS = []': 'ALLOWED_HOSTS should not be empty in production',
            'SECRET_KEY = "dev-key"': 'SECRET_KEY should be a secure random value',
            'DEBUG = True': 'DEBUG should be False in production'
        }
        
        for config, message in insecure_configs.items():
            if config in content:
                line_number = content.find(config) + 1
                line_number = content[:line_number].count('\n') + 1
                
                issue = SecurityIssue(
                    id=f"insecure_config_{line_number}",
                    title="Insecure configuration",
                    description=message,
                    severity=Severity.HIGH,
                    category=IssueCategory.CONFIGURATION,
                    file_path=file_path,
                    line_number=line_number,
                    fix_suggestion=f"Update configuration: {config}",
                    tags={"configuration", "insecure", "default"},
                    confidence=0.9,
                    rule_id="configuration.insecure"
                )
                issues.append(issue)
        
        return issues
