# SecurityScan 🔒

[![PyPI version](https://badge.fury.io/py/securityscan.svg)](https://badge.fury.io/py/securityscan)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/Sherin-SEF-AI/security-scan.svg)](https://github.com/Sherin-SEF-AI/security-scan)
[![GitHub forks](https://img.shields.io/github/forks/Sherin-SEF-AI/security-scan.svg)](https://github.com/Sherin-SEF-AI/security-scan)

> **Comprehensive security analysis for Python projects with a single command**

SecurityScan is a powerful Python security analysis tool that automatically detects vulnerabilities, hardcoded secrets, and security misconfigurations in your Python projects. Install it with pip and start scanning immediately - no configuration required!

## 🚀 Quick Start

```bash
# Install SecurityScan
pip install securityscan

# Scan your project
secscan .

# Scan with auto-fix for safe issues
secscan --fix .

# Generate HTML report
secscan --output html .
```

## ✨ Features

### 🔍 Comprehensive Security Scanning
- **Dependency Vulnerabilities**: Check against OSV, Safety DB, and PyUp.io
- **Hardcoded Secrets**: Detect API keys, passwords, tokens, and credentials
- **SQL Injection**: Find vulnerable SQL query patterns
- **Code Injection**: Detect dangerous functions like `eval()`, `exec()`
- **Framework Security**: Django, Flask, FastAPI specific checks
- **Cryptography Issues**: Weak algorithms, hardcoded salts
- **Authentication Issues**: Missing auth, weak passwords
- **XSS Detection**: Unescaped user input in templates

### 📊 Rich Reporting
- **Terminal Output**: Colored, interactive results with progress bars
- **HTML Reports**: Beautiful, interactive web reports
- **JSON/SARIF**: CI/CD integration ready
- **Markdown**: Documentation-friendly format

### ⚡ Smart Features
- **Auto-detection**: Automatically identifies project type and applies relevant rules
- **Incremental Scanning**: Only scan changed files for speed
- **Parallel Processing**: Fast scanning of large codebases
- **Configuration Support**: `.securityscan.yml` for team policies

## 🛠️ Installation

```bash
pip install securityscan
```

## 📖 Usage

### Basic Commands

```bash
# Scan current directory
secscan .

# Scan specific directory
secscan /path/to/project

# Quick scan (critical issues only)
secscan --quick .

# Deep scan (comprehensive analysis)
secscan --deep .

# Auto-fix safe issues
secscan --fix .

# Generate different output formats
secscan --output html .
secscan --output json .
secscan --output sarif .
```

### Advanced Options

```bash
# Custom configuration
secscan --config .securityscan.yml .

# Ignore specific files/patterns
secscan --ignore "tests/*,*.pyc" .

# Set severity threshold
secscan --severity high .

# Continuous monitoring
secscan --watch .

# Update vulnerability databases
secscan --update-db
```

## 📋 Configuration

Create a `.securityscan.yml` file in your project root:

```yaml
# SecurityScan Configuration
severity_threshold: medium
output_format: html

# Ignore patterns
ignore:
  - "tests/*"
  - "*.pyc"
  - "venv/*"

# Custom rules
rules:
  - id: custom-secret
    pattern: "SECRET_KEY.*=.*['\"](.*?)['\"]"
    severity: high
    message: "Custom secret pattern detected"

# Framework-specific settings
frameworks:
  django:
    check_debug: true
    check_csrf: true
  flask:
    check_debug: true
    check_secret_key: true
```

## 🎯 Supported Frameworks

- **Django**: Debug mode, CSRF protection, security middleware
- **Flask**: Debug mode, secret keys, Jinja2 rendering
- **FastAPI**: Input validation, CORS, exposed endpoints
- **Generic Python**: All security patterns apply

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Install SecurityScan
      run: pip install securityscan
    - name: Run Security Scan
      run: secscan --output sarif --fail-on high .
```

### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - pip install securityscan
    - secscan --output sarif .
  artifacts:
    reports:
      codequality: security-report.sarif
```

## 📈 Security Score

SecurityScan calculates a security score (0-100) based on:
- Number and severity of vulnerabilities
- Security best practices implemented
- Framework-specific security measures
- Dependency health

Perfect scores get special congratulations! 🎉

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://github.com/Sherin-SEF-AI/security-scan#readme)
- 🐛 [Issue Tracker](https://github.com/Sherin-SEF-AI/security-scan/issues)
- 💬 [Discussions](https://github.com/Sherin-SEF-AI/security-scan/discussions)

---

---

## 👨‍💻 Author

**SecurityScan** is created by [**Sherin Joseph Roy**](https://github.com/Sherin-SEF-AI), Co-Founder of [DeepMost AI](https://github.com/Sherin-SEF-AI) and creator of intelligent systems that bridge research and real-world safety.

- 🌐 **GitHub**: [@Sherin-SEF-AI](https://github.com/Sherin-SEF-AI)
- 💼 **LinkedIn**: [sherin-roy-deepmost](https://www.linkedin.com/in/sherin-roy-deepmost/)
- 📧 **Email**: sherin.joseph2217@gmail.com

---

**Made with ❤️ by [Sherin Joseph Roy](https://github.com/Sherin-SEF-AI)**
