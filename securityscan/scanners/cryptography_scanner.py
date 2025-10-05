"""Cryptography security scanner."""

from pathlib import Path
from typing import List

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory


class CryptographyScanner(BaseScanner):
    """Scanner for cryptography-related security issues."""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "cryptography"
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan file for cryptography security issues."""
        if self.should_skip_file(file_path) or not self.is_python_file(file_path):
            return []
        
        content = self.read_file_content(file_path)
        if not content:
            return []
        
        issues = []
        
        # Check for weak hashing algorithms
        issues.extend(self._check_weak_hash_algorithms(content, file_path))
        
        # Check for hardcoded salts
        issues.extend(self._check_hardcoded_salts(content, file_path))
        
        return issues
    
    def _check_weak_hash_algorithms(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check for weak hashing algorithms."""
        issues = []
        
        weak_algorithms = ['md5', 'sha1']
        
        for algorithm in weak_algorithms:
            if algorithm in content.lower():
                line_number = content.lower().find(algorithm) + 1
                line_number = content[:line_number].count('\n') + 1
                
                issue = SecurityIssue(
                    id=f"weak_hash_{algorithm}_{line_number}",
                    title=f"Weak hashing algorithm: {algorithm.upper()}",
                    description=f"Use of weak hashing algorithm {algorithm.upper()} detected. Use SHA-256 or stronger.",
                    severity=Severity.HIGH,
                    category=IssueCategory.CRYPTOGRAPHY,
                    file_path=file_path,
                    line_number=line_number,
                    fix_suggestion=f"Replace {algorithm.upper()} with SHA-256 or stronger algorithm",
                    tags={"cryptography", "weak_hash", algorithm},
                    confidence=0.8,
                    rule_id="cryptography.weak_hash"
                )
                issues.append(issue)
        
        return issues
    
    def _check_hardcoded_salts(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check for hardcoded salts."""
        issues = []
        
        if 'salt' in content.lower() and '=' in content:
            # Simple check for hardcoded salt values
            import re
            salt_pattern = r'salt\s*=\s*["\'][^"\']+["\']'
            
            for match in re.finditer(salt_pattern, content, re.IGNORECASE):
                line_number = content[:match.start()].count('\n') + 1
                
                issue = SecurityIssue(
                    id=f"hardcoded_salt_{line_number}",
                    title="Hardcoded salt value",
                    description="Hardcoded salt value detected. Use cryptographically secure random salt generation.",
                    severity=Severity.MEDIUM,
                    category=IssueCategory.CRYPTOGRAPHY,
                    file_path=file_path,
                    line_number=line_number,
                    fix_suggestion="Generate salt using os.urandom() or secrets.token_bytes()",
                    tags={"cryptography", "hardcoded_salt"},
                    confidence=0.7,
                    rule_id="cryptography.hardcoded_salt"
                )
                issues.append(issue)
        
        return issues
