"""
JSON report generator for SecurityScan.
"""

import json
from pathlib import Path
from typing import Dict, Any

from ..models import ScanResult


class JSONReporter:
    """JSON report generator."""
    
    def __init__(self, config):
        self.config = config
    
    def generate_report(self, result: ScanResult, output_file: Path):
        """Generate JSON report."""
        json_data = result.to_dict()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
