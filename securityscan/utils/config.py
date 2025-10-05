"""
Configuration management for SecurityScan.
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import yaml

from ..models import Severity


class SecurityScanConfig:
    """
    Configuration class for SecurityScan.
    
    Handles loading configuration from files, environment variables,
    and command line arguments with proper precedence.
    """
    
    # Default configuration
    DEFAULT_CONFIG = {
        # Scan options
        "scan_dependencies": True,
        "scan_secrets": True,
        "scan_sql_injection": True,
        "scan_code_injection": True,
        "scan_frameworks": True,
        "scan_cryptography": True,
        "scan_authentication": True,
        "scan_xss": True,
        "scan_configuration": True,
        
        # Performance options
        "parallel_scanning": True,
        "max_workers": 4,
        "follow_symlinks": False,
        
        # Filtering options
        "severity_threshold": Severity.INFO,
        "include_patterns": ["*.py", "*.pyi"],
        "exclude_patterns": [
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
        ],
        
        # Output options
        "output_format": "terminal",
        "output_file": None,
        "colored_output": True,
        "verbose": False,
        "quiet": False,
        
        # Database options
        "update_databases": False,
        "cache_duration": 3600,  # 1 hour
        
        # Framework-specific options
        "frameworks": {
            "django": {
                "check_debug": True,
                "check_csrf": True,
                "check_security_middleware": True,
            },
            "flask": {
                "check_debug": True,
                "check_secret_key": True,
                "check_jinja2": True,
            },
            "fastapi": {
                "check_validation": True,
                "check_cors": True,
                "check_exposed_endpoints": True,
            },
        },
        
        # Custom rules
        "custom_rules": [],
        "ignore_rules": [],
        
        # Auto-fix options
        "auto_fix": False,
        "backup_files": True,
        
        # Compliance frameworks
        "compliance": {
            "owasp": True,
            "pci_dss": False,
            "hipaa": False,
            "gdpr": False,
        },
    }
    
    def __init__(self, config_file: Optional[Path] = None, **kwargs):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to configuration file
            **kwargs: Override configuration values
        """
        self._config = self.DEFAULT_CONFIG.copy()
        
        # Load from config file if provided
        if config_file and config_file.exists():
            self.load_from_file(config_file)
        
        # Load from environment variables
        self.load_from_environment()
        
        # Apply command line overrides
        self.load_from_kwargs(**kwargs)
    
    def load_from_file(self, config_file: Path):
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = yaml.safe_load(f) or {}
            
            # Merge with existing config
            self._merge_config(file_config)
            
        except Exception as e:
            print(f"⚠️  Warning: Could not load config file {config_file}: {e}")
    
    def load_from_environment(self):
        """Load configuration from environment variables."""
        env_mappings = {
            'SECURITYSCAN_SEVERITY_THRESHOLD': ('severity_threshold', self._parse_severity),
            'SECURITYSCAN_OUTPUT_FORMAT': ('output_format', str),
            'SECURITYSCAN_OUTPUT_FILE': ('output_file', str),
            'SECURITYSCAN_COLORED_OUTPUT': ('colored_output', self._parse_bool),
            'SECURITYSCAN_VERBOSE': ('verbose', self._parse_bool),
            'SECURITYSCAN_QUIET': ('quiet', self._parse_bool),
            'SECURITYSCAN_PARALLEL_SCANNING': ('parallel_scanning', self._parse_bool),
            'SECURITYSCAN_MAX_WORKERS': ('max_workers', int),
            'SECURITYSCAN_AUTO_FIX': ('auto_fix', self._parse_bool),
            'SECURITYSCAN_UPDATE_DATABASES': ('update_databases', self._parse_bool),
        }
        
        for env_var, (config_key, parser) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    parsed_value = parser(value)
                    self._config[config_key] = parsed_value
                except Exception as e:
                    print(f"⚠️  Warning: Invalid value for {env_var}: {value} ({e})")
    
    def load_from_kwargs(self, **kwargs):
        """Load configuration from keyword arguments."""
        for key, value in kwargs.items():
            if key in self._config:
                self._config[key] = value
            elif key.startswith('scan_') and key[5:] in [
                'dependencies', 'secrets', 'sql_injection', 'code_injection',
                'frameworks', 'cryptography', 'authentication', 'xss', 'configuration'
            ]:
                self._config[key] = value
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Recursively merge configuration dictionaries."""
        for key, value in new_config.items():
            if key in self._config and isinstance(self._config[key], dict) and isinstance(value, dict):
                self._config[key].update(value)
            else:
                self._config[key] = value
    
    def _parse_severity(self, value: str) -> Severity:
        """Parse severity from string."""
        try:
            return Severity(value.lower())
        except ValueError:
            raise ValueError(f"Invalid severity: {value}")
    
    def _parse_bool(self, value: str) -> bool:
        """Parse boolean from string."""
        return value.lower() in ('true', '1', 'yes', 'on')
    
    @property
    def scan_dependencies(self) -> bool:
        return self._config['scan_dependencies']
    
    @scan_dependencies.setter
    def scan_dependencies(self, value: bool):
        self._config['scan_dependencies'] = value
    
    @property
    def scan_secrets(self) -> bool:
        return self._config['scan_secrets']
    
    @scan_secrets.setter
    def scan_secrets(self, value: bool):
        self._config['scan_secrets'] = value
    
    @property
    def scan_sql_injection(self) -> bool:
        return self._config['scan_sql_injection']
    
    @scan_sql_injection.setter
    def scan_sql_injection(self, value: bool):
        self._config['scan_sql_injection'] = value
    
    @property
    def scan_code_injection(self) -> bool:
        return self._config['scan_code_injection']
    
    @scan_code_injection.setter
    def scan_code_injection(self, value: bool):
        self._config['scan_code_injection'] = value
    
    @property
    def scan_frameworks(self) -> bool:
        return self._config['scan_frameworks']
    
    @scan_frameworks.setter
    def scan_frameworks(self, value: bool):
        self._config['scan_frameworks'] = value
    
    @property
    def scan_cryptography(self) -> bool:
        return self._config['scan_cryptography']
    
    @scan_cryptography.setter
    def scan_cryptography(self, value: bool):
        self._config['scan_cryptography'] = value
    
    @property
    def scan_authentication(self) -> bool:
        return self._config['scan_authentication']
    
    @scan_authentication.setter
    def scan_authentication(self, value: bool):
        self._config['scan_authentication'] = value
    
    @property
    def scan_xss(self) -> bool:
        return self._config['scan_xss']
    
    @scan_xss.setter
    def scan_xss(self, value: bool):
        self._config['scan_xss'] = value
    
    @property
    def scan_configuration(self) -> bool:
        return self._config['scan_configuration']
    
    @scan_configuration.setter
    def scan_configuration(self, value: bool):
        self._config['scan_configuration'] = value
    
    @property
    def severity_threshold(self) -> Severity:
        return self._config['severity_threshold']
    
    @severity_threshold.setter
    def severity_threshold(self, value: Severity):
        self._config['severity_threshold'] = value
    
    @property
    def include_patterns(self) -> List[str]:
        return self._config['include_patterns']
    
    @include_patterns.setter
    def include_patterns(self, value: List[str]):
        self._config['include_patterns'] = value
    
    @property
    def exclude_patterns(self) -> List[str]:
        return self._config['exclude_patterns']
    
    @exclude_patterns.setter
    def exclude_patterns(self, value: List[str]):
        self._config['exclude_patterns'] = value
    
    @property
    def parallel_scanning(self) -> bool:
        return self._config['parallel_scanning']
    
    @parallel_scanning.setter
    def parallel_scanning(self, value: bool):
        self._config['parallel_scanning'] = value
    
    @property
    def max_workers(self) -> int:
        return self._config['max_workers']
    
    @max_workers.setter
    def max_workers(self, value: int):
        self._config['max_workers'] = value
    
    @property
    def follow_symlinks(self) -> bool:
        return self._config['follow_symlinks']
    
    @property
    def output_format(self) -> str:
        return self._config['output_format']
    
    @output_format.setter
    def output_format(self, value: str):
        self._config['output_format'] = value
    
    @property
    def output_file(self) -> Optional[str]:
        return self._config['output_file']
    
    @output_file.setter
    def output_file(self, value: Optional[str]):
        self._config['output_file'] = value
    
    @property
    def colored_output(self) -> bool:
        return self._config['colored_output']
    
    @property
    def verbose(self) -> bool:
        return self._config['verbose']
    
    @verbose.setter
    def verbose(self, value: bool):
        self._config['verbose'] = value
    
    @property
    def quiet(self) -> bool:
        return self._config['quiet']
    
    @quiet.setter
    def quiet(self, value: bool):
        self._config['quiet'] = value
    
    @property
    def auto_fix(self) -> bool:
        return self._config['auto_fix']
    
    @auto_fix.setter
    def auto_fix(self, value: bool):
        self._config['auto_fix'] = value
    
    @property
    def frameworks(self) -> Dict[str, Dict[str, Any]]:
        return self._config['frameworks']
    
    @property
    def custom_rules(self) -> List[Dict[str, Any]]:
        return self._config['custom_rules']
    
    @property
    def compliance(self) -> Dict[str, bool]:
        return self._config['compliance']
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with default."""
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value."""
        self._config[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        config_dict = self._config.copy()
        
        # Convert enum objects to strings for JSON serialization
        if 'severity_threshold' in config_dict and isinstance(config_dict['severity_threshold'], Severity):
            config_dict['severity_threshold'] = config_dict['severity_threshold'].value
        
        return config_dict
    
    def save_to_file(self, config_file: Path):
        """Save configuration to YAML file."""
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(self._config, f, default_flow_style=False, indent=2)
    
    @classmethod
    def from_file(cls, config_file: Path) -> 'SecurityScanConfig':
        """Create configuration from file."""
        return cls(config_file=config_file)
    
    @classmethod
    def find_config_file(cls, project_path: Path) -> Optional[Path]:
        """Find configuration file in project directory."""
        config_names = [
            '.securityscan.yml',
            '.securityscan.yaml', 
            'securityscan.yml',
            'securityscan.yaml',
            '.secscan.yml',
            '.secscan.yaml',
        ]
        
        for config_name in config_names:
            config_path = project_path / config_name
            if config_path.exists():
                return config_path
        
        # Also check parent directories
        for parent in project_path.parents:
            for config_name in config_names:
                config_path = parent / config_name
                if config_path.exists():
                    return config_path
        
        return None
