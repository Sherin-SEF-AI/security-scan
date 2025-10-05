"""
SQL injection vulnerability scanner.
"""

from pathlib import Path
from typing import List, Dict, Any

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory


class SQLInjectionScanner(BaseScanner):
    """
    Scanner for SQL injection vulnerabilities.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "sql_injection"
        
        # SQL injection patterns
        self.sql_patterns = {
            'string_concat_sql': {
                'pattern': r'(?i)(select|insert|update|delete|drop|create|alter)\s+.*\+.*["\']',
                'severity': 'high',
                'category': 'sql_injection',
                'title': 'SQL String Concatenation',
                'description': 'SQL query uses string concatenation which can lead to SQL injection',
                'cwe_id': 'CWE-89',
                'fix': 'Use parameterized queries instead of string concatenation',
                'tags': ['sql_injection', 'string_concatenation']
            },
            'f_string_sql': {
                'pattern': r'(?i)(select|insert|update|delete|drop|create|alter)\s+.*f["\'].*\{.*\}',
                'severity': 'high',
                'category': 'sql_injection',
                'title': 'SQL with f-string formatting',
                'description': 'SQL query uses f-string formatting which can lead to SQL injection',
                'cwe_id': 'CWE-89',
                'fix': 'Use parameterized queries instead of f-string formatting',
                'tags': ['sql_injection', 'f_string']
            },
            'format_sql': {
                'pattern': r'(?i)(select|insert|update|delete|drop|create|alter)\s+.*\.format\(',
                'severity': 'high',
                'category': 'sql_injection',
                'title': 'SQL with .format() method',
                'description': 'SQL query uses .format() method which can lead to SQL injection',
                'cwe_id': 'CWE-89',
                'fix': 'Use parameterized queries instead of .format() method',
                'tags': ['sql_injection', 'format_method']
            },
            'percent_format_sql': {
                'pattern': r'(?i)(select|insert|update|delete|drop|create|alter)\s+.*%[sd]',
                'severity': 'high',
                'category': 'sql_injection',
                'title': 'SQL with % formatting',
                'description': 'SQL query uses % formatting which can lead to SQL injection',
                'cwe_id': 'CWE-89',
                'fix': 'Use parameterized queries instead of % formatting',
                'tags': ['sql_injection', 'percent_format']
            },
            'raw_sql_execute': {
                'pattern': r'(?i)\.execute\s*\(\s*["\'].*["\']\s*\)',
                'severity': 'medium',
                'category': 'sql_injection',
                'title': 'Raw SQL execution',
                'description': 'Raw SQL query execution detected - verify it uses parameterized queries',
                'cwe_id': 'CWE-89',
                'fix': 'Ensure the SQL query uses parameterized queries',
                'tags': ['sql_injection', 'raw_sql']
            }
        }
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan file for SQL injection vulnerabilities."""
        if self.should_skip_file(file_path) or not self.is_python_file(file_path):
            return []
        
        content = self.read_file_content(file_path)
        if not content:
            return []
        
        issues = []
        
        # Scan with patterns
        issues.extend(self.find_pattern_matches(content, self.sql_patterns, file_path))
        
        # Check for dangerous SQL functions
        dangerous_functions = ['execute', 'executemany', 'executescript']
        issues.extend(self.find_function_calls(content, dangerous_functions, file_path))
        
        return issues
