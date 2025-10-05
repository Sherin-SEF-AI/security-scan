"""
Base scanner class for all security scanners.
"""

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

from ..models import SecurityIssue, Severity, IssueCategory
from ..utils.config import SecurityScanConfig


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.
    
    Provides common functionality for file scanning, pattern matching,
    and issue creation.
    """
    
    def __init__(self, config: SecurityScanConfig):
        """Initialize the scanner with configuration."""
        self.config = config
        self.name = self.__class__.__name__.replace('Scanner', '').lower()
        
    @abstractmethod
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """
        Scan a single file for security issues.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of security issues found
        """
        pass
    
    def read_file_content(self, file_path: Path) -> Optional[str]:
        """
        Safely read file content with error handling.
        
        Args:
            file_path: Path to file
            
        Returns:
            File content as string, or None if read fails
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except (OSError, IOError, UnicodeDecodeError):
            return None
    
    def find_pattern_matches(
        self, 
        content: str, 
        patterns: Dict[str, Dict[str, Any]],
        file_path: Path,
        context_lines: int = 3
    ) -> List[SecurityIssue]:
        """
        Find pattern matches in file content.
        
        Args:
            content: File content to search
            patterns: Dictionary of patterns with metadata
            file_path: Path to the file being scanned
            context_lines: Number of context lines to include
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = content.splitlines()
        
        for pattern_name, pattern_data in patterns.items():
            pattern = pattern_data.get('pattern', '')
            severity = Severity(pattern_data.get('severity', 'medium'))
            category = IssueCategory(pattern_data.get('category', 'general'))
            title = pattern_data.get('title', f'Pattern match: {pattern_name}')
            description = pattern_data.get('description', '')
            fix_suggestion = pattern_data.get('fix', '')
            cwe_id = pattern_data.get('cwe_id')
            cve_id = pattern_data.get('cve_id')
            references = pattern_data.get('references', [])
            tags = set(pattern_data.get('tags', []))
            confidence = pattern_data.get('confidence', 1.0)
            
            try:
                # Compile pattern for better performance
                compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                
                for match in compiled_pattern.finditer(content):
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Skip if severity is below threshold
                    if severity.numeric_value < self.config.severity_threshold.numeric_value:
                        continue
                    
                    # Get code snippet with context
                    code_snippet = self._get_code_snippet(lines, line_number, context_lines)
                    
                    # Create issue
                    issue = SecurityIssue(
                        id=f"{self.name}_{pattern_name}_{line_number}",
                        title=title,
                        description=description.format(match=match),
                        severity=severity,
                        category=category,
                        file_path=file_path,
                        line_number=line_number,
                        column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                        code_snippet=code_snippet,
                        fix_suggestion=fix_suggestion,
                        cwe_id=cwe_id,
                        cve_id=cve_id,
                        references=references,
                        tags=tags,
                        confidence=confidence,
                        rule_id=f"{self.name}.{pattern_name}",
                    )
                    
                    issues.append(issue)
                    
            except re.error as e:
                # Skip invalid regex patterns
                continue
        
        return issues
    
    def _get_code_snippet(
        self, 
        lines: List[str], 
        line_number: int, 
        context_lines: int = 3
    ) -> str:
        """
        Get code snippet with context around the line number.
        
        Args:
            lines: List of file lines
            line_number: Target line number (1-indexed)
            context_lines: Number of context lines
            
        Returns:
            Code snippet as string
        """
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)
        
        snippet_lines = []
        for i in range(start_line, end_line):
            line_num = i + 1
            prefix = ">>> " if line_num == line_number else "    "
            snippet_lines.append(f"{prefix}{line_num:4d}: {lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def find_function_calls(
        self, 
        content: str, 
        function_names: List[str],
        file_path: Path
    ) -> List[SecurityIssue]:
        """
        Find dangerous function calls in code.
        
        Args:
            content: File content to search
            function_names: List of function names to find
            file_path: Path to the file being scanned
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = content.splitlines()
        
        for func_name in function_names:
            # Pattern to find function calls
            pattern = rf'\b{re.escape(func_name)}\s*\('
            
            try:
                compiled_pattern = re.compile(pattern, re.IGNORECASE)
                
                for match in compiled_pattern.finditer(content):
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Get the full line
                    line_content = lines[line_number - 1] if line_number <= len(lines) else ""
                    
                    # Create issue
                    issue = SecurityIssue(
                        id=f"{self.name}_dangerous_function_{line_number}",
                        title=f"Dangerous function call: {func_name}",
                        description=f"Use of dangerous function '{func_name}' detected. "
                                  f"This function can execute arbitrary code and should be avoided.",
                        severity=Severity.HIGH,
                        category=IssueCategory.CODE_INJECTION,
                        file_path=file_path,
                        line_number=line_number,
                        column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                        code_snippet=self._get_code_snippet(lines, line_number),
                        fix_suggestion=f"Remove or replace '{func_name}' with safer alternatives. "
                                     f"Never use with user input.",
                        cwe_id="CWE-94",
                        references=[
                            "https://cwe.mitre.org/data/definitions/94.html",
                            "https://owasp.org/www-community/attacks/Code_Injection"
                        ],
                        tags={"dangerous_function", "code_injection"},
                        confidence=0.9,
                        rule_id=f"{self.name}.dangerous_function",
                        metadata={"function_name": func_name}
                    )
                    
                    issues.append(issue)
                    
            except re.error:
                continue
        
        return issues
    
    def find_import_statements(
        self, 
        content: str, 
        module_names: List[str],
        file_path: Path
    ) -> List[SecurityIssue]:
        """
        Find specific import statements.
        
        Args:
            content: File content to search
            module_names: List of module names to find
            file_path: Path to the file being scanned
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = content.splitlines()
        
        for module_name in module_names:
            # Pattern to find import statements
            patterns = [
                rf'import\s+{re.escape(module_name)}',
                rf'from\s+{re.escape(module_name)}\s+import',
            ]
            
            for pattern in patterns:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    
                    for match in compiled_pattern.finditer(content):
                        line_number = content[:match.start()].count('\n') + 1
                        
                        # Create issue
                        issue = SecurityIssue(
                            id=f"{self.name}_import_{module_name}_{line_number}",
                            title=f"Import of potentially dangerous module: {module_name}",
                            description=f"Import of module '{module_name}' detected. "
                                      f"This module may have security implications.",
                            severity=Severity.MEDIUM,
                            category=IssueCategory.CODE_INJECTION,
                            file_path=file_path,
                            line_number=line_number,
                            column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                            code_snippet=self._get_code_snippet(lines, line_number),
                            fix_suggestion=f"Review the usage of '{module_name}' and ensure "
                                         f"it's necessary and secure.",
                            tags={"import", "module"},
                            confidence=0.7,
                            rule_id=f"{self.name}.import",
                            metadata={"module_name": module_name}
                        )
                        
                        issues.append(issue)
                        
                except re.error:
                    continue
        
        return issues
    
    def should_skip_file(self, file_path: Path) -> bool:
        """
        Check if file should be skipped based on configuration.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file should be skipped
        """
        # Check exclude patterns
        for pattern in self.config.exclude_patterns:
            if file_path.match(pattern):
                return True
        
        # Check file size
        try:
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                return True
        except (OSError, IOError):
            return True
        
        return False
    
    def get_file_extension(self, file_path: Path) -> str:
        """Get file extension in lowercase."""
        return file_path.suffix.lower()
    
    def is_python_file(self, file_path: Path) -> bool:
        """Check if file is a Python file."""
        return file_path.suffix.lower() in ['.py', '.pyi']
    
    def is_config_file(self, file_path: Path) -> bool:
        """Check if file is a configuration file."""
        config_extensions = ['.ini', '.cfg', '.conf', '.yaml', '.yml', '.toml', '.json']
        return file_path.suffix.lower() in config_extensions
    
    def is_dependency_file(self, file_path: Path) -> bool:
        """Check if file is a dependency file."""
        dependency_files = [
            'requirements.txt', 'requirements-dev.txt', 'requirements-test.txt',
            'Pipfile', 'poetry.lock', 'pyproject.toml', 'setup.py', 'setup.cfg',
            'environment.yml', 'conda.yml'
        ]
        return file_path.name in dependency_files
    
    def create_issue(
        self,
        issue_id: str,
        title: str,
        description: str,
        severity: Severity,
        category: IssueCategory,
        file_path: Path,
        line_number: int,
        **kwargs
    ) -> SecurityIssue:
        """
        Create a security issue with default values.
        
        Args:
            issue_id: Unique issue identifier
            title: Issue title
            description: Issue description
            severity: Issue severity
            category: Issue category
            file_path: Path to file with issue
            line_number: Line number where issue occurs
            **kwargs: Additional issue properties
            
        Returns:
            SecurityIssue object
        """
        return SecurityIssue(
            id=f"{self.name}_{issue_id}",
            title=title,
            description=description,
            severity=severity,
            category=category,
            file_path=file_path,
            line_number=line_number,
            rule_id=f"{self.name}.{issue_id}",
            **kwargs
        )
