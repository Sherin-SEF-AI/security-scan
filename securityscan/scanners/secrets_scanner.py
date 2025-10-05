"""
Secrets detection scanner.

Scans for hardcoded secrets, API keys, passwords, tokens, and credentials
in source code and configuration files.
"""

import base64
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

from .base import BaseScanner
from ..models import SecurityIssue, Severity, IssueCategory
from ..utils.config import SecurityScanConfig


class SecretsScanner(BaseScanner):
    """
    Scanner for hardcoded secrets and credentials.
    """
    
    def __init__(self, config: SecurityScanConfig):
        super().__init__(config)
        self.name = "secrets"
        
        # Define secret patterns
        self.secret_patterns = self._initialize_secret_patterns()
        
        # Common false positives to exclude
        self.false_positive_patterns = {
            r'example\.com',
            r'localhost',
            r'127\.0\.0\.1',
            r'0\.0\.0\.0',
            r'your_.*_here',
            r'placeholder',
            r'changeme',
            r'secret_key_here',
            r'api_key_here',
            r'password_here',
            r'token_here',
            r'key_here',
            r'<.*>',  # HTML-like placeholders
            r'\{.*\}',  # Template placeholders
            r'%s',  # String formatting
            r'{}',  # Empty format strings
        }
    
    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan file for hardcoded secrets."""
        if self.should_skip_file(file_path):
            return []
        
        content = self.read_file_content(file_path)
        if not content:
            return []
        
        issues = []
        
        # Scan for different types of secrets
        issues.extend(self._scan_api_keys(content, file_path))
        issues.extend(self._scan_passwords(content, file_path))
        issues.extend(self._scan_tokens(content, file_path))
        issues.extend(self._scan_database_urls(content, file_path))
        issues.extend(self._scan_private_keys(content, file_path))
        issues.extend(self._scan_certificates(content, file_path))
        issues.extend(self._scan_aws_credentials(content, file_path))
        issues.extend(self._scan_google_credentials(content, file_path))
        issues.extend(self._scan_azure_credentials(content, file_path))
        issues.extend(self._scan_github_tokens(content, file_path))
        issues.extend(self._scan_stripe_keys(content, file_path))
        issues.extend(self._scan_twilio_credentials(content, file_path))
        issues.extend(self._scan_sendgrid_keys(content, file_path))
        issues.extend(self._scan_jwt_secrets(content, file_path))
        issues.extend(self._scan_oauth_tokens(content, file_path))
        issues.extend(self._scan_webhook_urls(content, file_path))
        issues.extend(self._scan_base64_secrets(content, file_path))
        issues.extend(self._scan_email_addresses(content, file_path))
        issues.extend(self._scan_ip_addresses(content, file_path))
        issues.extend(self._scan_internal_urls(content, file_path))
        
        return issues
    
    def _initialize_secret_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize patterns for different types of secrets."""
        return {
            # API Keys
            'api_key': {
                'pattern': r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
                'severity': 'high',
                'category': 'secret',
                'title': 'Hardcoded API Key',
                'description': 'Potential API key found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['api_key', 'secret', 'hardcoded']
            },
            
            # Passwords
            'password': {
                'pattern': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
                'severity': 'critical',
                'category': 'secret',
                'title': 'Hardcoded Password',
                'description': 'Hardcoded password found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['password', 'secret', 'hardcoded']
            },
            
            # Tokens
            'token': {
                'pattern': r'(?i)(token|bearer)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
                'severity': 'high',
                'category': 'secret',
                'title': 'Hardcoded Token',
                'description': 'Hardcoded authentication token found',
                'cwe_id': 'CWE-798',
                'tags': ['token', 'secret', 'hardcoded']
            },
            
            # Database URLs
            'database_url': {
                'pattern': r'(?i)(database_url|db_url|mysql://|postgres://|postgresql://|mongodb://|redis://|sqlite://)\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
                'severity': 'high',
                'category': 'secret',
                'title': 'Hardcoded Database URL',
                'description': 'Database connection string with credentials found',
                'cwe_id': 'CWE-798',
                'tags': ['database', 'secret', 'hardcoded']
            },
            
            # AWS Credentials
            'aws_access_key': {
                'pattern': r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']?([A-Z0-9]{20,})["\']?',
                'severity': 'critical',
                'category': 'secret',
                'title': 'AWS Credentials',
                'description': 'AWS access key or secret found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['aws', 'secret', 'hardcoded']
            },
            
            # Google Cloud
            'google_credentials': {
                'pattern': r'(?i)(google[_-]?application[_-]?credentials|gcp[_-]?key|google[_-]?api[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
                'severity': 'critical',
                'category': 'secret',
                'title': 'Google Cloud Credentials',
                'description': 'Google Cloud credentials found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['google', 'gcp', 'secret', 'hardcoded']
            },
            
            # Azure
            'azure_credentials': {
                'pattern': r'(?i)(azure[_-]?key|azure[_-]?secret|azure[_-]?connection[_-]?string)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
                'severity': 'critical',
                'category': 'secret',
                'title': 'Azure Credentials',
                'description': 'Azure credentials found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['azure', 'secret', 'hardcoded']
            },
            
            # GitHub
            'github_token': {
                'pattern': r'(?i)(github[_-]?token|gh[_-]?token|github[_-]?key)\s*[=:]\s*["\']?(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})["\']?',
                'severity': 'high',
                'category': 'secret',
                'title': 'GitHub Token',
                'description': 'GitHub personal access token found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['github', 'secret', 'hardcoded']
            },
            
            # Stripe
            'stripe_key': {
                'pattern': r'(?i)(stripe[_-]?key|stripe[_-]?secret[_-]?key)\s*[=:]\s*["\']?(sk_[a-zA-Z0-9]{24,}|pk_[a-zA-Z0-9]{24,})["\']?',
                'severity': 'critical',
                'category': 'secret',
                'title': 'Stripe API Key',
                'description': 'Stripe API key found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['stripe', 'secret', 'hardcoded']
            },
            
            # Twilio
            'twilio_credentials': {
                'pattern': r'(?i)(twilio[_-]?sid|twilio[_-]?token|twilio[_-]?auth[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
                'severity': 'high',
                'category': 'secret',
                'title': 'Twilio Credentials',
                'description': 'Twilio credentials found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['twilio', 'secret', 'hardcoded']
            },
            
            # SendGrid
            'sendgrid_key': {
                'pattern': r'(?i)(sendgrid[_-]?key|sendgrid[_-]?api[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{40,})["\']?',
                'severity': 'high',
                'category': 'secret',
                'title': 'SendGrid API Key',
                'description': 'SendGrid API key found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['sendgrid', 'secret', 'hardcoded']
            },
            
            # JWT Secrets
            'jwt_secret': {
                'pattern': r'(?i)(jwt[_-]?secret|jwt[_-]?key|json[_-]?web[_-]?token[_-]?secret)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
                'severity': 'high',
                'category': 'secret',
                'title': 'JWT Secret',
                'description': 'JWT secret key found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['jwt', 'secret', 'hardcoded']
            },
            
            # OAuth
            'oauth_token': {
                'pattern': r'(?i)(oauth[_-]?token|oauth[_-]?secret|client[_-]?secret)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
                'severity': 'high',
                'category': 'secret',
                'title': 'OAuth Token/Secret',
                'description': 'OAuth token or client secret found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['oauth', 'secret', 'hardcoded']
            },
            
            # Private Keys
            'private_key': {
                'pattern': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                'severity': 'critical',
                'category': 'secret',
                'title': 'Private Key',
                'description': 'Private key found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['private_key', 'secret', 'hardcoded']
            },
            
            # Certificates
            'certificate': {
                'pattern': r'-----BEGIN\s+CERTIFICATE-----.*?-----END\s+CERTIFICATE-----',
                'severity': 'high',
                'category': 'secret',
                'title': 'Certificate',
                'description': 'Certificate found in source code',
                'cwe_id': 'CWE-798',
                'tags': ['certificate', 'secret', 'hardcoded']
            }
        }
    
    def _scan_api_keys(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for API keys."""
        return self._scan_with_patterns(content, file_path, ['api_key'])
    
    def _scan_passwords(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for passwords."""
        return self._scan_with_patterns(content, file_path, ['password'])
    
    def _scan_tokens(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for tokens."""
        return self._scan_with_patterns(content, file_path, ['token'])
    
    def _scan_database_urls(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for database URLs."""
        return self._scan_with_patterns(content, file_path, ['database_url'])
    
    def _scan_private_keys(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for private keys."""
        return self._scan_with_patterns(content, file_path, ['private_key'])
    
    def _scan_certificates(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for certificates."""
        return self._scan_with_patterns(content, file_path, ['certificate'])
    
    def _scan_aws_credentials(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for AWS credentials."""
        return self._scan_with_patterns(content, file_path, ['aws_access_key'])
    
    def _scan_google_credentials(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for Google Cloud credentials."""
        return self._scan_with_patterns(content, file_path, ['google_credentials'])
    
    def _scan_azure_credentials(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for Azure credentials."""
        return self._scan_with_patterns(content, file_path, ['azure_credentials'])
    
    def _scan_github_tokens(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for GitHub tokens."""
        return self._scan_with_patterns(content, file_path, ['github_token'])
    
    def _scan_stripe_keys(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for Stripe keys."""
        return self._scan_with_patterns(content, file_path, ['stripe_key'])
    
    def _scan_twilio_credentials(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for Twilio credentials."""
        return self._scan_with_patterns(content, file_path, ['twilio_credentials'])
    
    def _scan_sendgrid_keys(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for SendGrid keys."""
        return self._scan_with_patterns(content, file_path, ['sendgrid_key'])
    
    def _scan_jwt_secrets(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for JWT secrets."""
        return self._scan_with_patterns(content, file_path, ['jwt_secret'])
    
    def _scan_oauth_tokens(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for OAuth tokens."""
        return self._scan_with_patterns(content, file_path, ['oauth_token'])
    
    def _scan_webhook_urls(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for webhook URLs with embedded tokens."""
        issues = []
        
        # Pattern for webhook URLs with tokens
        webhook_pattern = r'(?i)(webhook[_-]?url|callback[_-]?url|notify[_-]?url)\s*[=:]\s*["\']?(https?://[^"\'\s]*[?&](?:token|key|secret)=[a-zA-Z0-9_\-\.]+)["\']?'
        
        for match in re.finditer(webhook_pattern, content):
            line_number = content[:match.start()].count('\n') + 1
            
            issue = SecurityIssue(
                id=f"webhook_url_{line_number}",
                title="Webhook URL with embedded token",
                description=f"Webhook URL with embedded authentication token found: {match.group(2)[:50]}...",
                severity=Severity.HIGH,
                category=IssueCategory.SECRET,
                file_path=file_path,
                line_number=line_number,
                column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                code_snippet=self._get_code_snippet(content.splitlines(), line_number),
                fix_suggestion="Use environment variables or secure configuration management for webhook URLs with tokens",
                cwe_id="CWE-798",
                references=["https://cwe.mitre.org/data/definitions/798.html"],
                tags={"webhook", "secret", "hardcoded", "url"},
                confidence=0.9,
                rule_id="secrets.webhook_url",
                metadata={"webhook_url": match.group(2)}
            )
            issues.append(issue)
        
        return issues
    
    def _scan_base64_secrets(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for base64 encoded secrets."""
        issues = []
        
        # Pattern for base64 strings
        base64_pattern = r'["\']?([A-Za-z0-9+/]{40,}={0,2})["\']?'
        
        for match in re.finditer(base64_pattern, content):
            base64_string = match.group(1)
            
            # Skip if it's likely not a secret (too short, common patterns)
            if len(base64_string) < 40:
                continue
            
            # Try to decode and check if it looks like a secret
            try:
                decoded = base64.b64decode(base64_string).decode('utf-8', errors='ignore')
                
                # Check if decoded content looks like a secret
                if self._looks_like_secret(decoded):
                    line_number = content[:match.start()].count('\n') + 1
                    
                    issue = SecurityIssue(
                        id=f"base64_secret_{line_number}",
                        title="Base64 encoded secret",
                        description=f"Potential base64 encoded secret found. Decoded content: {decoded[:50]}...",
                        severity=Severity.MEDIUM,
                        category=IssueCategory.SECRET,
                        file_path=file_path,
                        line_number=line_number,
                        column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                        code_snippet=self._get_code_snippet(content.splitlines(), line_number),
                        fix_suggestion="Use environment variables or secure configuration management instead of base64 encoded secrets",
                        cwe_id="CWE-798",
                        tags={"base64", "secret", "encoded"},
                        confidence=0.6,
                        rule_id="secrets.base64",
                        metadata={"base64_string": base64_string, "decoded_content": decoded}
                    )
                    issues.append(issue)
            
            except Exception:
                # Not valid base64 or can't decode
                continue
        
        return issues
    
    def _scan_email_addresses(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for hardcoded email addresses that might be sensitive."""
        issues = []
        
        # Pattern for email addresses
        email_pattern = r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
        
        for match in re.finditer(email_pattern, content):
            email = match.group(1)
            
            # Skip common test/example emails
            if any(domain in email.lower() for domain in ['example.com', 'test.com', 'localhost', 'dummy.com']):
                continue
            
            # Check if it's in a sensitive context
            context_start = max(0, match.start() - 50)
            context_end = min(len(content), match.end() + 50)
            context = content[context_start:context_end].lower()
            
            sensitive_keywords = ['admin', 'root', 'administrator', 'support', 'security', 'noreply']
            if any(keyword in context for keyword in sensitive_keywords):
                line_number = content[:match.start()].count('\n') + 1
                
                issue = SecurityIssue(
                    id=f"email_address_{line_number}",
                    title="Hardcoded email address",
                    description=f"Email address found in source code: {email}",
                    severity=Severity.LOW,
                    category=IssueCategory.SECRET,
                    file_path=file_path,
                    line_number=line_number,
                    column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                    code_snippet=self._get_code_snippet(content.splitlines(), line_number),
                    fix_suggestion="Consider using environment variables for email addresses",
                    tags={"email", "hardcoded"},
                    confidence=0.5,
                    rule_id="secrets.email",
                    metadata={"email_address": email}
                )
                issues.append(issue)
        
        return issues
    
    def _scan_ip_addresses(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for hardcoded IP addresses."""
        issues = []
        
        # Pattern for IP addresses
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        for match in re.finditer(ip_pattern, content):
            ip = match.group(0)
            
            # Skip common test/localhost IPs
            if ip in ['127.0.0.1', '0.0.0.0', '192.168.0.1', '10.0.0.1']:
                continue
            
            # Check if it's in a sensitive context
            context_start = max(0, match.start() - 30)
            context_end = min(len(content), match.end() + 30)
            context = content[context_start:context_end].lower()
            
            sensitive_keywords = ['server', 'host', 'endpoint', 'api', 'database', 'internal']
            if any(keyword in context for keyword in sensitive_keywords):
                line_number = content[:match.start()].count('\n') + 1
                
                issue = SecurityIssue(
                    id=f"ip_address_{line_number}",
                    title="Hardcoded IP address",
                    description=f"IP address found in source code: {ip}",
                    severity=Severity.LOW,
                    category=IssueCategory.SECRET,
                    file_path=file_path,
                    line_number=line_number,
                    column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                    code_snippet=self._get_code_snippet(content.splitlines(), line_number),
                    fix_suggestion="Use environment variables or configuration files for IP addresses",
                    tags={"ip", "hardcoded", "network"},
                    confidence=0.5,
                    rule_id="secrets.ip_address",
                    metadata={"ip_address": ip}
                )
                issues.append(issue)
        
        return issues
    
    def _scan_internal_urls(self, content: str, file_path: Path) -> List[SecurityIssue]:
        """Scan for hardcoded internal URLs."""
        issues = []
        
        # Pattern for URLs
        url_pattern = r'(?i)(https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s"\']*)'
        
        for match in re.finditer(url_pattern, content):
            url = match.group(1)
            
            # Skip common public domains
            public_domains = ['google.com', 'github.com', 'stackoverflow.com', 'example.com', 'httpbin.org']
            if any(domain in url.lower() for domain in public_domains):
                continue
            
            # Check if it looks like an internal URL
            internal_indicators = ['internal', 'dev', 'staging', 'test', 'localhost', '192.168.', '10.', '172.']
            if any(indicator in url.lower() for indicator in internal_indicators):
                line_number = content[:match.start()].count('\n') + 1
                
                issue = SecurityIssue(
                    id=f"internal_url_{line_number}",
                    title="Hardcoded internal URL",
                    description=f"Internal URL found in source code: {url}",
                    severity=Severity.MEDIUM,
                    category=IssueCategory.SECRET,
                    file_path=file_path,
                    line_number=line_number,
                    column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                    code_snippet=self._get_code_snippet(content.splitlines(), line_number),
                    fix_suggestion="Use environment variables or configuration files for internal URLs",
                    tags={"url", "hardcoded", "internal"},
                    confidence=0.7,
                    rule_id="secrets.internal_url",
                    metadata={"internal_url": url}
                )
                issues.append(issue)
        
        return issues
    
    def _scan_with_patterns(self, content: str, file_path: Path, pattern_names: List[str]) -> List[SecurityIssue]:
        """Scan content with specific secret patterns."""
        issues = []
        
        for pattern_name in pattern_names:
            if pattern_name not in self.secret_patterns:
                continue
            
            pattern_data = self.secret_patterns[pattern_name]
            pattern = pattern_data['pattern']
            
            try:
                compiled_pattern = re.compile(pattern, re.MULTILINE | re.DOTALL)
                
                for match in compiled_pattern.finditer(content):
                    # Check if this is a false positive
                    if self._is_false_positive(match.group(0)):
                        continue
                    
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Skip if severity is below threshold
                    severity = Severity(pattern_data['severity'])
                    if severity.numeric_value < self.config.severity_threshold.numeric_value:
                        continue
                    
                    # Create issue
                    issue = SecurityIssue(
                        id=f"secret_{pattern_name}_{line_number}",
                        title=pattern_data['title'],
                        description=pattern_data['description'],
                        severity=severity,
                        category=IssueCategory.SECRET,
                        file_path=file_path,
                        line_number=line_number,
                        column_number=match.start() - content.rfind('\n', 0, match.start()) - 1,
                        code_snippet=self._get_code_snippet(content.splitlines(), line_number),
                        fix_suggestion="Use environment variables or secure configuration management instead of hardcoded secrets",
                        cwe_id=pattern_data.get('cwe_id'),
                        references=["https://cwe.mitre.org/data/definitions/798.html"],
                        tags=set(pattern_data.get('tags', [])),
                        confidence=0.9,
                        rule_id=f"secrets.{pattern_name}",
                        metadata={"secret_type": pattern_name, "matched_text": match.group(0)}
                    )
                    issues.append(issue)
                    
            except re.error:
                # Skip invalid regex patterns
                continue
        
        return issues
    
    def _is_false_positive(self, matched_text: str) -> bool:
        """Check if a match is likely a false positive."""
        matched_text_lower = matched_text.lower()
        
        for pattern in self.false_positive_patterns:
            try:
                if re.search(pattern, matched_text_lower, re.IGNORECASE):
                    return True
            except re.error:
                continue
        
        return False
    
    def _looks_like_secret(self, text: str) -> bool:
        """Check if decoded text looks like a secret."""
        # Simple heuristics to determine if text looks like a secret
        if len(text) < 10:
            return False
        
        # Check for common secret patterns
        secret_indicators = [
            'password', 'secret', 'key', 'token', 'credential',
            'access', 'private', 'auth', 'login', 'api'
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in secret_indicators)
