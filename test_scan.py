#!/usr/bin/env python3
"""
Simple test script to demonstrate SecurityScan functionality.
"""

import os
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from securityscan.core import SecurityScanner
from securityscan.utils.config import SecurityScanConfig
from securityscan.models import Severity


def create_test_files():
    """Create some test files with security issues."""
    test_dir = Path("test_project")
    test_dir.mkdir(exist_ok=True)
    
    # Create a Python file with security issues
    test_py_content = '''
import os
import subprocess
import hashlib

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"
DATABASE_URL = "postgresql://user:password@localhost:5432/db"

# SQL injection vulnerability
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

# Code injection vulnerability
def execute_command(command):
    result = eval(command)  # Dangerous!
    return result

# Weak cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Dangerous subprocess call
def run_command(cmd):
    subprocess.call(cmd, shell=True)  # Shell injection risk

# Django debug mode
DEBUG = True
SECRET_KEY = "dev-secret-key"
'''
    
    (test_dir / "app.py").write_text(test_py_content)
    
    # Create requirements.txt with vulnerable package
    requirements_content = '''
requests==2.20.0
django==2.0.0
flask==1.0.0
'''
    
    (test_dir / "requirements.txt").write_text(requirements_content)
    
    print(f"Created test files in {test_dir}")
    return test_dir


def main():
    """Run a test scan."""
    print("🔒 SecurityScan Test")
    print("=" * 50)
    
    # Create test files
    test_dir = create_test_files()
    
    # Configure scanner
    config = SecurityScanConfig(
        scan_dependencies=True,
        scan_secrets=True,
        scan_sql_injection=True,
        scan_code_injection=True,
        scan_frameworks=True,
        scan_cryptography=True,
        scan_authentication=True,
        scan_xss=True,
        scan_configuration=True,
        severity_threshold=Severity.INFO
    )
    
    # Initialize scanner
    scanner = SecurityScanner(config)
    
    # Run scan
    print(f"Scanning {test_dir}...")
    result = scanner.scan(test_dir)
    
    # Print results
    print(f"\nScan completed!")
    print(f"Security Score: {result.statistics.security_score}/100")
    print(f"Total Issues: {result.statistics.total_issues}")
    
    if result.issues:
        print(f"\nIssues found:")
        for issue in result.issues[:5]:  # Show first 5 issues
            print(f"  {issue.severity.value.upper()}: {issue.title}")
            print(f"    File: {issue.file_path}:{issue.line_number}")
            print(f"    Description: {issue.description}")
            print()
    
    # Clean up
    import shutil
    shutil.rmtree(test_dir)
    print("Test files cleaned up.")


if __name__ == "__main__":
    main()
