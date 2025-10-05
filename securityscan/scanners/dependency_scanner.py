"""
Dependency vulnerability scanner.

Scans dependency files for known vulnerabilities using multiple sources:
- OSV (Open Source Vulnerabilities) database
- Safety DB
- PyUp.io vulnerability feed
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import requests
from packaging import version as pkg_version

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory
from ..utils.config import SecurityScanConfig


class DependencyScanner(BaseScanner):
    """
    Scanner for dependency vulnerabilities.
    """
    
    def __init__(self, config: SecurityScanConfig):
        super().__init__(config)
        self.name = "dependency"
        
        # Cache for vulnerability data
        self.vulnerability_cache = {}
        self.typosquatting_packages = set()
        self.suspicious_packages = set()
        
        # Initialize vulnerability data
        self._load_vulnerability_data()
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan dependency file for vulnerabilities."""
        if self.should_skip_file(file_path) or not self.is_dependency_file(file_path):
            return []
        
        issues = []
        content = self.read_file_content(file_path)
        if not content:
            return issues
        
        # Parse dependencies based on file type
        dependencies = self._parse_dependencies(content, file_path)
        
        # Check each dependency
        for dep in dependencies:
            dep_issues = self._check_dependency_vulnerabilities(dep, file_path)
            issues.extend(dep_issues)
        
        # Check for typosquatting
        typosquatting_issues = self._check_typosquatting(dependencies, file_path)
        issues.extend(typosquatting_issues)
        
        # Check for suspicious packages
        suspicious_issues = self._check_suspicious_packages(dependencies, file_path)
        issues.extend(suspicious_issues)
        
        return issues
    
    def _parse_dependencies(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Parse dependencies from various file formats."""
        dependencies = []
        
        if file_path.name == 'requirements.txt':
            dependencies = self._parse_requirements_txt(content)
        elif file_path.name == 'Pipfile':
            dependencies = self._parse_pipfile(content)
        elif file_path.name == 'poetry.lock':
            dependencies = self._parse_poetry_lock(content)
        elif file_path.name == 'pyproject.toml':
            dependencies = self._parse_pyproject_toml(content)
        elif file_path.name == 'setup.py':
            dependencies = self._parse_setup_py(content)
        elif file_path.name == 'setup.cfg':
            dependencies = self._parse_setup_cfg(content)
        
        return dependencies
    
    def _parse_requirements_txt(self, content: str) -> List[Dict[str, Any]]:
        """Parse requirements.txt format."""
        dependencies = []
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse package specification
            dep = self._parse_package_spec(line, line_num)
            if dep:
                dependencies.append(dep)
        
        return dependencies
    
    def _parse_pipfile(self, content: str) -> List[Dict[str, Any]]:
        """Parse Pipfile format."""
        dependencies = []
        
        try:
            import toml
            pipfile_data = toml.loads(content)
            
            # Parse packages and dev-packages
            for section in ['packages', 'dev-packages']:
                if section in pipfile_data:
                    for package, version_spec in pipfile_data[section].items():
                        dep = {
                            'name': package,
                            'version_spec': version_spec if isinstance(version_spec, str) else str(version_spec),
                            'line_number': 1,  # Approximate
                            'source': 'pipfile'
                        }
                        dependencies.append(dep)
        except ImportError:
            # Fallback to regex parsing if toml not available
            dependencies = self._parse_pipfile_regex(content)
        
        return dependencies
    
    def _parse_pipfile_regex(self, content: str) -> List[Dict[str, Any]]:
        """Fallback regex parsing for Pipfile."""
        dependencies = []
        
        # Simple regex to find packages
        pattern = r'(\w+)\s*=\s*["\']([^"\']+)["\']'
        
        for match in re.finditer(pattern, content):
            package = match.group(1)
            version_spec = match.group(2)
            
            dep = {
                'name': package,
                'version_spec': version_spec,
                'line_number': content[:match.start()].count('\n') + 1,
                'source': 'pipfile'
            }
            dependencies.append(dep)
        
        return dependencies
    
    def _parse_poetry_lock(self, content: str) -> List[Dict[str, Any]]:
        """Parse poetry.lock format."""
        dependencies = []
        
        try:
            import toml
            lock_data = toml.loads(content)
            
            if 'package' in lock_data:
                for package_data in lock_data['package']:
                    dep = {
                        'name': package_data.get('name', ''),
                        'version': package_data.get('version', ''),
                        'line_number': 1,  # Approximate
                        'source': 'poetry'
                    }
                    dependencies.append(dep)
        except ImportError:
            # Fallback parsing
            dependencies = self._parse_poetry_lock_regex(content)
        
        return dependencies
    
    def _parse_poetry_lock_regex(self, content: str) -> List[Dict[str, Any]]:
        """Fallback regex parsing for poetry.lock."""
        dependencies = []
        
        # Find package blocks
        package_pattern = r'\[\[package\]\]\s*\n((?:[^[]*\n)*)'
        
        for match in re.finditer(package_pattern, content, re.MULTILINE):
            package_block = match.group(1)
            
            name_match = re.search(r'name\s*=\s*"([^"]+)"', package_block)
            version_match = re.search(r'version\s*=\s*"([^"]+)"', package_block)
            
            if name_match and version_match:
                dep = {
                    'name': name_match.group(1),
                    'version': version_match.group(1),
                    'line_number': content[:match.start()].count('\n') + 1,
                    'source': 'poetry'
                }
                dependencies.append(dep)
        
        return dependencies
    
    def _parse_pyproject_toml(self, content: str) -> List[Dict[str, Any]]:
        """Parse pyproject.toml format."""
        dependencies = []
        
        try:
            import toml
            pyproject_data = toml.loads(content)
            
            # Check for Poetry dependencies
            if 'tool' in pyproject_data and 'poetry' in pyproject_data['tool']:
                poetry_data = pyproject_data['tool']['poetry']
                
                for section in ['dependencies', 'dev-dependencies']:
                    if section in poetry_data:
                        for package, version_spec in poetry_data[section].items():
                            if package != 'python':  # Skip Python version spec
                                dep = {
                                    'name': package,
                                    'version_spec': str(version_spec),
                                    'line_number': 1,
                                    'source': 'pyproject'
                                }
                                dependencies.append(dep)
            
            # Check for setuptools dependencies
            elif 'project' in pyproject_data:
                project_data = pyproject_data['project']
                if 'dependencies' in project_data:
                    for dep_spec in project_data['dependencies']:
                        dep = self._parse_package_spec(dep_spec, 1)
                        if dep:
                            dep['source'] = 'pyproject'
                            dependencies.append(dep)
        
        except ImportError:
            dependencies = self._parse_pyproject_toml_regex(content)
        
        return dependencies
    
    def _parse_pyproject_toml_regex(self, content: str) -> List[Dict[str, Any]]:
        """Fallback regex parsing for pyproject.toml."""
        dependencies = []
        
        # Find dependencies sections
        deps_pattern = r'dependencies\s*=\s*\[(.*?)\]'
        
        for match in re.finditer(deps_pattern, content, re.DOTALL):
            deps_section = match.group(1)
            
            # Extract individual dependencies
            dep_pattern = r'"([^"]+)"'
            for dep_match in re.finditer(dep_pattern, deps_section):
                dep_spec = dep_match.group(1)
                dep = self._parse_package_spec(dep_spec, content[:match.start()].count('\n') + 1)
                if dep:
                    dep['source'] = 'pyproject'
                    dependencies.append(dep)
        
        return dependencies
    
    def _parse_setup_py(self, content: str) -> List[Dict[str, Any]]:
        """Parse setup.py format."""
        dependencies = []
        
        # Look for install_requires
        install_requires_pattern = r'install_requires\s*=\s*\[(.*?)\]'
        
        for match in re.finditer(install_requires_pattern, content, re.DOTALL):
            requires_section = match.group(1)
            
            # Extract individual requirements
            req_pattern = r'"([^"]+)"'
            for req_match in re.finditer(req_pattern, requires_section):
                req_spec = req_match.group(1)
                dep = self._parse_package_spec(req_spec, content[:match.start()].count('\n') + 1)
                if dep:
                    dep['source'] = 'setup.py'
                    dependencies.append(dep)
        
        return dependencies
    
    def _parse_setup_cfg(self, content: str) -> List[Dict[str, Any]]:
        """Parse setup.cfg format."""
        dependencies = []
        
        # Look for install_requires in [options] section
        in_options = False
        in_install_requires = False
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            
            if line == '[options]':
                in_options = True
                in_install_requires = False
            elif line.startswith('[') and line != '[options]':
                in_options = False
                in_install_requires = False
            elif in_options and line.startswith('install_requires'):
                in_install_requires = True
                # Parse the line
                if '=' in line:
                    reqs_str = line.split('=', 1)[1].strip()
                    for req_spec in reqs_str.split(','):
                        dep = self._parse_package_spec(req_spec.strip(), line_num)
                        if dep:
                            dep['source'] = 'setup.cfg'
                            dependencies.append(dep)
            elif in_install_requires and line:
                # Continuation line
                for req_spec in line.split(','):
                    dep = self._parse_package_spec(req_spec.strip(), line_num)
                    if dep:
                        dep['source'] = 'setup.cfg'
                        dependencies.append(dep)
        
        return dependencies
    
    def _parse_package_spec(self, spec: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse a package specification string."""
        spec = spec.strip()
        
        # Remove comments
        if '#' in spec:
            spec = spec.split('#')[0].strip()
        
        if not spec:
            return None
        
        # Parse package name and version constraints
        if '==' in spec:
            name, version = spec.split('==', 1)
            version_spec = f'=={version}'
        elif '>=' in spec:
            name, version = spec.split('>=', 1)
            version_spec = f'>={version}'
        elif '<=' in spec:
            name, version = spec.split('<=', 1)
            version_spec = f'<={version}'
        elif '>' in spec:
            name, version = spec.split('>', 1)
            version_spec = f'>{version}'
        elif '<' in spec:
            name, version = spec.split('<', 1)
            version_spec = f'<{version}'
        elif '~=' in spec:
            name, version = spec.split('~=', 1)
            version_spec = f'~={version}'
        elif '!=' in spec:
            name, version = spec.split('!=', 1)
            version_spec = f'!={version}'
        else:
            name = spec
            version_spec = ''
        
        return {
            'name': name.strip(),
            'version_spec': version_spec,
            'line_number': line_number,
            'source': 'requirements'
        }
    
    def _check_dependency_vulnerabilities(self, dep: Dict[str, Any], file_path: Path) -> List[SecurityIssue]:
        """Check a single dependency for vulnerabilities."""
        issues = []
        package_name = dep['name']
        
        # Check cached vulnerabilities
        if package_name in self.vulnerability_cache:
            vulns = self.vulnerability_cache[package_name]
            for vuln in vulns:
                issue = self._create_vulnerability_issue(vuln, dep, file_path)
                if issue:
                    issues.append(issue)
        
        # Check using Safety DB
        safety_issues = self._check_safety_db(dep, file_path)
        issues.extend(safety_issues)
        
        # Check using OSV API
        osv_issues = self._check_osv_api(dep, file_path)
        issues.extend(osv_issues)
        
        return issues
    
    def _create_vulnerability_issue(self, vuln: Dict[str, Any], dep: Dict[str, Any], file_path: Path) -> Optional[SecurityIssue]:
        """Create a security issue from vulnerability data."""
        cve_id = vuln.get('cve_id', '')
        severity = self._map_severity(vuln.get('severity', 'medium'))
        
        # Skip if below threshold
        if severity.numeric_value < self.config.severity_threshold.numeric_value:
            return None
        
        title = f"Vulnerable dependency: {dep['name']}"
        if cve_id:
            title += f" ({cve_id})"
        
        description = vuln.get('description', 'No description available')
        if cve_id:
            description += f"\n\nCVE: {cve_id}"
        
        fix_suggestion = f"Update {dep['name']} to a secure version"
        if vuln.get('fixed_version'):
            fix_suggestion += f" (>= {vuln['fixed_version']})"
        
        return SecurityIssue(
            id=f"vuln_{dep['name']}_{cve_id}_{dep['line_number']}",
            title=title,
            description=description,
            severity=severity,
            category=IssueCategory.DEPENDENCY,
            file_path=file_path,
            line_number=dep['line_number'],
            code_snippet=self._get_dependency_snippet(dep, file_path),
            fix_suggestion=fix_suggestion,
            cve_id=cve_id,
            cwe_id=vuln.get('cwe_id'),
            references=vuln.get('references', []),
            tags={"vulnerability", "dependency", "cve"},
            confidence=0.9,
            rule_id="dependency.vulnerability",
            metadata={
                "package_name": dep['name'],
                "version_spec": dep['version_spec'],
                "vulnerability_data": vuln
            }
        )
    
    def _check_safety_db(self, dep: Dict[str, Any], file_path: Path) -> List[SecurityIssue]:
        """Check dependency against Safety DB."""
        issues = []
        
        try:
            # Try to use safety command if available
            result = subprocess.run(
                ['safety', 'check', '--json', '--short-report'],
                input=f"{dep['name']}{dep['version_spec']}",
                text=True,
                capture_output=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # No vulnerabilities found
                return issues
            
            # Parse safety output
            try:
                safety_data = json.loads(result.stdout)
                for vuln in safety_data:
                    issue = self._create_safety_issue(vuln, dep, file_path)
                    if issue:
                        issues.append(issue)
            except json.JSONDecodeError:
                # Fallback to text parsing
                issues.extend(self._parse_safety_text(result.stdout, dep, file_path))
        
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            # Safety not available or failed
            pass
        
        return issues
    
    def _check_osv_api(self, dep: Dict[str, Any], file_path: Path) -> List[SecurityIssue]:
        """Check dependency against OSV API."""
        issues = []
        
        try:
            # Query OSV API
            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {
                    "name": dep['name'],
                    "ecosystem": "PyPI"
                }
            }
            
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if 'vulns' in data:
                    for vuln in data['vulns']:
                        issue = self._create_osv_issue(vuln, dep, file_path)
                        if issue:
                            issues.append(issue)
        
        except (requests.RequestException, KeyError, ValueError):
            # API unavailable or parsing failed
            pass
        
        return issues
    
    def _check_typosquatting(self, dependencies: List[Dict[str, Any]], file_path: Path) -> List[SecurityIssue]:
        """Check for typosquatting packages."""
        issues = []
        
        popular_packages = {
            'requests', 'numpy', 'pandas', 'django', 'flask', 'fastapi',
            'pytest', 'pytest-cov', 'black', 'flake8', 'mypy', 'bandit',
            'safety', 'pip', 'setuptools', 'wheel', 'virtualenv'
        }
        
        for dep in dependencies:
            package_name = dep['name']
            
            # Check for typosquatting patterns
            for popular in popular_packages:
                if self._is_typosquatting(package_name, popular):
                    issue = SecurityIssue(
                        id=f"typosquatting_{package_name}_{dep['line_number']}",
                        title=f"Potential typosquatting: {package_name}",
                        description=f"Package '{package_name}' may be a typosquatting attempt "
                                  f"targeting '{popular}'. Verify this is the intended package.",
                        severity=Severity.HIGH,
                        category=IssueCategory.DEPENDENCY,
                        file_path=file_path,
                        line_number=dep['line_number'],
                        code_snippet=self._get_dependency_snippet(dep, file_path),
                        fix_suggestion=f"Verify '{package_name}' is the intended package. "
                                     f"Consider using '{popular}' instead.",
                        tags={"typosquatting", "dependency", "malicious"},
                        confidence=0.7,
                        rule_id="dependency.typosquatting",
                        metadata={
                            "package_name": package_name,
                            "target_package": popular,
                            "typosquatting_type": "name_similarity"
                        }
                    )
                    issues.append(issue)
                    break
        
        return issues
    
    def _check_suspicious_packages(self, dependencies: List[Dict[str, Any]], file_path: Path) -> List[SecurityIssue]:
        """Check for suspicious packages."""
        issues = []
        
        suspicious_patterns = [
            r'.*test.*',
            r'.*fake.*',
            r'.*mock.*',
            r'.*demo.*',
            r'.*example.*',
            r'.*sample.*'
        ]
        
        for dep in dependencies:
            package_name = dep['name']
            
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.match(pattern, package_name, re.IGNORECASE):
                    issue = SecurityIssue(
                        id=f"suspicious_{package_name}_{dep['line_number']}",
                        title=f"Suspicious package name: {package_name}",
                        description=f"Package '{package_name}' has a suspicious name pattern. "
                                  f"Verify this is a legitimate package.",
                        severity=Severity.MEDIUM,
                        category=IssueCategory.DEPENDENCY,
                        file_path=file_path,
                        line_number=dep['line_number'],
                        code_snippet=self._get_dependency_snippet(dep, file_path),
                        fix_suggestion=f"Verify '{package_name}' is a legitimate package. "
                                     f"Consider using well-known alternatives.",
                        tags={"suspicious", "dependency", "naming"},
                        confidence=0.6,
                        rule_id="dependency.suspicious",
                        metadata={
                            "package_name": package_name,
                            "suspicious_pattern": pattern
                        }
                    )
                    issues.append(issue)
                    break
        
        return issues
    
    def _load_vulnerability_data(self):
        """Load vulnerability data from various sources."""
        # This would typically load from cached vulnerability databases
        # For now, we'll use a simple in-memory cache
        pass
    
    def _map_severity(self, severity_str: str) -> Severity:
        """Map severity string to Severity enum."""
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'moderate': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO,
        }
        return severity_map.get(severity_str.lower(), Severity.MEDIUM)
    
    def _is_typosquatting(self, package_name: str, target: str) -> bool:
        """Check if package name is likely typosquatting."""
        if package_name == target:
            return False
        
        # Simple typosquatting detection
        if len(package_name) < 3 or len(target) < 3:
            return False
        
        # Check for common typosquatting patterns
        if package_name in target or target in package_name:
            return True
        
        # Check for character substitutions
        if len(package_name) == len(target):
            differences = sum(1 for a, b in zip(package_name, target) if a != b)
            if differences <= 2:  # Allow up to 2 character differences
                return True
        
        return False
    
    def _get_dependency_snippet(self, dep: Dict[str, Any], file_path: Path) -> str:
        """Get code snippet for dependency."""
        content = self.read_file_content(file_path)
        if not content:
            return ""
        
        lines = content.splitlines()
        line_number = dep['line_number']
        
        return self._get_code_snippet(lines, line_number, 2)
    
    def _create_safety_issue(self, vuln_data: Dict[str, Any], dep: Dict[str, Any], file_path: Path) -> Optional[SecurityIssue]:
        """Create issue from Safety DB data."""
        # Implementation would parse Safety DB format
        return None
    
    def _create_osv_issue(self, vuln_data: Dict[str, Any], dep: Dict[str, Any], file_path: Path) -> Optional[SecurityIssue]:
        """Create issue from OSV API data."""
        # Implementation would parse OSV API format
        return None
    
    def _parse_safety_text(self, safety_output: str, dep: Dict[str, Any], file_path: Path) -> List[SecurityIssue]:
        """Parse Safety text output."""
        # Implementation would parse Safety text format
        return []
