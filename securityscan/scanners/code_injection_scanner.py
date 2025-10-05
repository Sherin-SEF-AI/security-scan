"""
Code injection vulnerability scanner.
"""

from pathlib import Path
from typing import List

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory


class CodeInjectionScanner(BaseScanner):
    """
    Scanner for code injection vulnerabilities.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "code_injection"
        
        # Dangerous functions that can execute code
        self.dangerous_functions = [
            'eval', 'exec', 'compile', '__import__', 'execfile',
            'reload', 'input', 'raw_input'
        ]
        
        # Dangerous imports
        self.dangerous_imports = [
            'os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen',
            'pickle.loads', 'pickle.load', 'marshal.loads', 'marshal.load'
        ]
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan file for code injection vulnerabilities."""
        if self.should_skip_file(file_path) or not self.is_python_file(file_path):
            return []
        
        content = self.read_file_content(file_path)
        if not content:
            return []
        
        issues = []
        
        # Check for dangerous function calls
        issues.extend(self.find_function_calls(content, self.dangerous_functions, file_path))
        
        # Check for dangerous imports
        issues.extend(self.find_import_statements(content, self.dangerous_imports, file_path))
        
        # Check for shell=True in subprocess calls
        issues.extend(self._check_subprocess_shell(content, file_path))
        
        # Check for YAML unsafe loading
        issues.extend(self._check_yaml_unsafe_loading(content, file_path))
        
        return issues
    
    def _check_subprocess_shell(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check for subprocess calls with shell=True."""
        issues = []
        
        # Pattern for subprocess calls with shell=True
        pattern = r'subprocess\.(call|run|Popen|check_call|check_output)\s*\([^)]*shell\s*=\s*True'
        
        for match in self._find_pattern_matches(content, pattern):
            line_number = content[:match.start()].count('\n') + 1
            
            issue = SecurityIssue(
                id=f"subprocess_shell_{line_number}",
                title="Subprocess with shell=True",
                description="Subprocess call with shell=True detected. This can lead to shell injection vulnerabilities.",
                severity=Severity.HIGH,
                category=IssueCategory.CODE_INJECTION,
                file_path=file_path,
                line_number=line_number,
                column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                code_snippet=self._get_code_snippet(content.splitlines(), line_number),
                fix_suggestion="Avoid using shell=True. Use list of arguments instead of shell commands.",
                cwe_id="CWE-78",
                references=[
                    "https://cwe.mitre.org/data/definitions/78.html",
                    "https://docs.python.org/3/library/subprocess.html#security-considerations"
                ],
                tags={"subprocess", "shell_injection", "code_injection"},
                confidence=0.9,
                rule_id="code_injection.subprocess_shell"
            )
            issues.append(issue)
        
        return issues
    
    def _check_yaml_unsafe_loading(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Check for unsafe YAML loading."""
        issues = []
        
        # Pattern for yaml.load() instead of yaml.safe_load()
        pattern = r'yaml\.load\s*\('
        
        for match in self._find_pattern_matches(content, pattern):
            line_number = content[:match.start()].count('\n') + 1
            
            issue = SecurityIssue(
                id=f"yaml_unsafe_load_{line_number}",
                title="Unsafe YAML loading",
                description="yaml.load() is unsafe and can execute arbitrary code. Use yaml.safe_load() instead.",
                severity=Severity.HIGH,
                category=IssueCategory.CODE_INJECTION,
                file_path=file_path,
                line_number=line_number,
                column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                code_snippet=self._get_code_snippet(content.splitlines(), line_number),
                fix_suggestion="Replace yaml.load() with yaml.safe_load() for safe YAML parsing.",
                cwe_id="CWE-502",
                references=[
                    "https://cwe.mitre.org/data/definitions/502.html",
                    "https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation"
                ],
                tags={"yaml", "deserialization", "code_injection"},
                confidence=0.9,
                rule_id="code_injection.yaml_unsafe_load"
            )
            issues.append(issue)
        
        return issues
    
    def _find_pattern_matches(self, content: str, pattern: str):
        """Find pattern matches in content."""
        import re
        return re.finditer(pattern, content, re.IGNORECASE)
