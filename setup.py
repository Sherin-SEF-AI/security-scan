#!/usr/bin/env python3
"""
Setup configuration for securityscan package.
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Comprehensive security analysis for Python projects"

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return [
        'requests>=2.31.0',
        'colorama>=0.4.6',
        'pyyaml>=6.0',
        'jinja2>=3.1.2',
        'click>=8.1.0',
        'rich>=13.0.0',
        'safety>=2.3.5',
        'bandit>=1.7.5',
        'semgrep>=1.40.0',
        'packaging>=23.0',
        'pip-audit>=2.6.1',
        'cryptography>=41.0.0',
    ]

setup(
    name="securityscan",
    version="1.0.0",
    author="Sherin Joseph Roy",
    author_email="sherin.joseph2217@gmail.com",
    description="Comprehensive security analysis for Python projects with a single command",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/Sherin-SEF-AI/security-scan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "secscan=securityscan.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "securityscan": [
            "rules/*.yml",
            "templates/*.html",
            "data/*.json",
        ],
    },
    keywords="security, vulnerability, scanning, python, static-analysis, dependency-check",
    project_urls={
        "Bug Reports": "https://github.com/Sherin-SEF-AI/security-scan/issues",
        "Source": "https://github.com/Sherin-SEF-AI/security-scan",
        "Documentation": "https://github.com/Sherin-SEF-AI/security-scan#readme",
        "Author LinkedIn": "https://www.linkedin.com/in/sherin-roy-deepmost/",
        "Author GitHub": "https://github.com/Sherin-SEF-AI",
    },
)
