"""
File discovery utilities for SecurityScan.
"""

import fnmatch
from pathlib import Path
from typing import List, Set, Optional

from .config import SecurityScanConfig


def discover_python_files(
    project_path: Path,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    follow_symlinks: bool = False,
    max_file_size: int = 10 * 1024 * 1024  # 10MB
) -> List[Path]:
    """
    Discover all Python files in the project.
    
    Args:
        project_path: Root path to search
        include_patterns: Patterns to include (default: *.py, *.pyi)
        exclude_patterns: Patterns to exclude
        follow_symlinks: Whether to follow symbolic links
        max_file_size: Maximum file size to scan (bytes)
        
    Returns:
        List of Python file paths
    """
    if include_patterns is None:
        include_patterns = ["*.py", "*.pyi"]
    
    if exclude_patterns is None:
        exclude_patterns = [
            "*/__pycache__/*",
            "*/.git/*",
            "*/node_modules/*",
            "*/venv/*",
            "*/env/*",
            "*/virtualenv/*",
            "*/site-packages/*",
            "*/build/*",
            "*/dist/*",
            "*/tests/*",
            "*/test_*",
            "*_test.py",
            "*/migrations/*",
            "*/__init__.py",
            "*/setup.py",
            "*/conftest.py",
        ]
    
    discovered_files = []
    visited_dirs = set()
    
    def should_exclude_path(path: Path) -> bool:
        """Check if path should be excluded."""
        path_str = str(path)
        
        # Check file size
        try:
            if path.is_file() and path.stat().st_size > max_file_size:
                return True
        except (OSError, IOError):
            return True
        
        # Check exclude patterns
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(path_str, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
        
        return False
    
    def should_include_file(path: Path) -> bool:
        """Check if file should be included."""
        for pattern in include_patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return True
        return False
    
    def scan_directory(directory: Path):
        """Recursively scan directory for Python files."""
        if should_exclude_path(directory):
            return
        
        # Avoid infinite loops with symlinks
        try:
            real_path = directory.resolve()
            if real_path in visited_dirs:
                return
            visited_dirs.add(real_path)
        except (OSError, IOError):
            return
        
        try:
            for item in directory.iterdir():
                if should_exclude_path(item):
                    continue
                
                if item.is_file():
                    if should_include_file(item):
                        discovered_files.append(item)
                elif item.is_dir():
                    if not follow_symlinks and item.is_symlink():
                        continue
                    scan_directory(item)
        
        except (PermissionError, OSError, IOError):
            # Skip directories we can't read
            pass
    
    scan_directory(project_path)
    
    # Sort files for consistent ordering
    discovered_files.sort()
    
    return discovered_files


def get_project_type(project_path: Path) -> str:
    """
    Detect the type of Python project.
    
    Args:
        project_path: Path to project root
        
    Returns:
        Project type string
    """
    project_files = {
        'requirements.txt': 'pip',
        'Pipfile': 'pipenv',
        'poetry.lock': 'poetry',
        'pyproject.toml': 'poetry',
        'setup.py': 'setuptools',
        'setup.cfg': 'setuptools',
        'environment.yml': 'conda',
    }
    
    framework_files = {
        'manage.py': 'django',
        'settings.py': 'django',
        'app.py': 'flask',
        'main.py': 'fastapi',
        'asgi.py': 'django',
        'wsgi.py': 'django',
    }
    
    # Check for project management files
    for file_name, project_type in project_files.items():
        if (project_path / file_name).exists():
            return project_type
    
    # Check for framework files
    for file_name, framework in framework_files.items():
        if (project_path / file_name).exists():
            return framework
    
    # Check subdirectories for framework indicators
    for item in project_path.iterdir():
        if item.is_dir():
            # Django apps
            if (item / 'models.py').exists() and (item / 'views.py').exists():
                return 'django'
            
            # Flask blueprints
            if (item / '__init__.py').exists() and 'blueprint' in item.name.lower():
                return 'flask'
    
    return 'generic'


def get_dependency_files(project_path: Path) -> List[Path]:
    """
    Find all dependency files in the project.
    
    Args:
        project_path: Path to project root
        
    Returns:
        List of dependency file paths
    """
    dependency_files = []
    
    dependency_patterns = [
        'requirements*.txt',
        'Pipfile',
        'poetry.lock',
        'pyproject.toml',
        'setup.py',
        'setup.cfg',
        'environment.yml',
        'conda.yml',
    ]
    
    for pattern in dependency_patterns:
        if pattern.endswith('*.txt'):
            # Handle requirements files with variants
            for file_path in project_path.glob(pattern):
                dependency_files.append(file_path)
        else:
            file_path = project_path / pattern
            if file_path.exists():
                dependency_files.append(file_path)
    
    return dependency_files


def get_config_files(project_path: Path) -> List[Path]:
    """
    Find all configuration files in the project.
    
    Args:
        project_path: Path to project root
        
    Returns:
        List of configuration file paths
    """
    config_files = []
    
    config_patterns = [
        '*.env*',
        '*.ini',
        '*.cfg',
        '*.conf',
        '*.yaml',
        '*.yml',
        '*.toml',
        '*.json',
        'settings.py',
        'config.py',
        'django_settings.py',
        'local_settings.py',
        'production_settings.py',
        'development_settings.py',
    ]
    
    for pattern in config_patterns:
        for file_path in project_path.rglob(pattern):
            # Skip certain directories
            if any(skip_dir in str(file_path) for skip_dir in ['__pycache__', '.git', 'node_modules']):
                continue
            config_files.append(file_path)
    
    return config_files


def is_test_file(file_path: Path) -> bool:
    """
    Check if a file is a test file.
    
    Args:
        file_path: Path to file
        
    Returns:
        True if file appears to be a test file
    """
    test_indicators = [
        'test_',
        '_test',
        'tests/',
        '/test/',
        'spec_',
        '_spec',
    ]
    
    file_str = str(file_path)
    name = file_path.name.lower()
    
    # Check filename patterns
    for indicator in test_indicators:
        if indicator in file_str.lower():
            return True
    
    # Check for test directory
    if 'test' in file_path.parts:
        return True
    
    return False


def is_generated_file(file_path: Path) -> bool:
    """
    Check if a file appears to be generated.
    
    Args:
        file_path: Path to file
        
    Returns:
        True if file appears to be generated
    """
    generated_indicators = [
        'migrations/',
        '__pycache__/',
        '.pyc',
        '.pyo',
        'build/',
        'dist/',
        '.egg-info/',
        'generated',
        'auto_',
        '_generated',
    ]
    
    file_str = str(file_path)
    
    for indicator in generated_indicators:
        if indicator in file_str:
            return True
    
    return False


def estimate_file_complexity(file_path: Path) -> int:
    """
    Estimate the complexity of a Python file.
    
    Args:
        file_path: Path to Python file
        
    Returns:
        Complexity score (higher = more complex)
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Simple complexity metrics
        lines = content.splitlines()
        line_count = len([line for line in lines if line.strip()])
        
        # Count various complexity indicators
        complexity_indicators = [
            'if ', 'elif ', 'else:',
            'for ', 'while ',
            'try:', 'except ', 'finally:',
            'with ',
            'def ', 'class ',
            'import ', 'from ',
            'lambda ',
            'and ', 'or ',
            'not ',
        ]
        
        complexity_score = line_count
        
        for indicator in complexity_indicators:
            complexity_score += content.count(indicator) * 2
        
        return complexity_score
        
    except (OSError, IOError, UnicodeDecodeError):
        return 0
