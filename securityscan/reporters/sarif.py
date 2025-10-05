"""
SARIF report generator for SecurityScan.
"""

import json
from pathlib import Path
from typing import Dict, Any, List

from ..models import ScanResult, Severity


class SARIFReporter:
    """SARIF report generator for GitHub Security tab integration."""
    
    def __init__(self, config):
        self.config = config
    
    def generate_report(self, result: ScanResult, output_file: Path):
        """Generate SARIF report."""
        sarif_data = self._generate_sarif_data(result)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
    
    def _generate_sarif_data(self, result: ScanResult) -> Dict[str, Any]:
        """Generate SARIF data structure."""
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecurityScan",
                            "version": result.scanner_version,
                            "informationUri": "https://github.com/securityscan/securityscan",
                            "rules": self._generate_rules(result)
                        }
                    },
                    "artifacts": self._generate_artifacts(result),
                    "results": self._generate_results(result)
                }
            ]
        }
    
    def _generate_rules(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Generate SARIF rules."""
        rules = []
        rule_ids = set()
        
        for issue in result.issues:
            if issue.rule_id and issue.rule_id not in rule_ids:
                rule_ids.add(issue.rule_id)
                
                rule = {
                    "id": issue.rule_id,
                    "name": issue.title,
                    "shortDescription": {
                        "text": issue.description[:100] + "..." if len(issue.description) > 100 else issue.description
                    },
                    "fullDescription": {
                        "text": issue.description
                    },
                    "defaultConfiguration": {
                        "level": self._map_severity_to_sarif_level(issue.severity)
                    }
                }
                
                if issue.cwe_id:
                    rule["properties"] = {
                        "cwe": issue.cwe_id
                    }
                
                if issue.references:
                    rule["helpUri"] = issue.references[0]
                
                rules.append(rule)
        
        return rules
    
    def _generate_artifacts(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Generate SARIF artifacts."""
        artifacts = []
        file_paths = set()
        
        for issue in result.issues:
            if str(issue.file_path) not in file_paths:
                file_paths.add(str(issue.file_path))
                
                artifact = {
                    "location": {
                        "uri": str(issue.file_path.relative_to(result.project_path))
                    }
                }
                
                artifacts.append(artifact)
        
        return artifacts
    
    def _generate_results(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Generate SARIF results."""
        results = []
        
        for i, issue in enumerate(result.issues):
            sarif_result = {
                "ruleId": issue.rule_id or f"securityscan.{issue.category.value}",
                "ruleIndex": i,
                "level": self._map_severity_to_sarif_level(issue.severity),
                "message": {
                    "text": issue.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(issue.file_path.relative_to(result.project_path))
                            },
                            "region": {
                                "startLine": issue.line_number,
                                "startColumn": issue.column_number + 1 if issue.column_number > 0 else 1
                            }
                        }
                    }
                ],
                "properties": {
                    "security-severity": issue.severity.value,
                    "tags": list(issue.tags) if issue.tags else []
                }
            }
            
            if issue.cve_id:
                sarif_result["properties"]["cve"] = issue.cve_id
            
            if issue.fix_suggestion:
                sarif_result["fixes"] = [
                    {
                        "description": {
                            "text": issue.fix_suggestion
                        }
                    }
                ]
            
            results.append(sarif_result)
        
        return results
    
    def _map_severity_to_sarif_level(self, severity: Severity) -> str:
        """Map SecurityScan severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error", 
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping.get(severity, "note")
