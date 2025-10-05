"""
Core security scanner engine.
"""

import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import ScanResult, SecurityIssue, Severity, IssueCategory, ScanStatistics
from .scanners import (
    DependencyScanner,
    SecretsScanner, 
    SQLInjectionScanner,
    CodeInjectionScanner,
    FrameworkScanner,
    CryptographyScanner,
    AuthenticationScanner,
    XSSScanner,
    ConfigurationScanner,
)
from .utils.config import SecurityScanConfig
from .utils.file_discovery import discover_python_files
from .utils.progress import ProgressTracker


class SecurityScanner:
    """
    Main security scanner that orchestrates all scanning modules.
    """
    
    def __init__(self, config: Optional[SecurityScanConfig] = None):
        """Initialize the security scanner."""
        self.config = config or SecurityScanConfig()
        self.scanners = self._initialize_scanners()
        self.progress_tracker = ProgressTracker()
        
    def _initialize_scanners(self) -> List[Any]:
        """Initialize all available scanners based on configuration."""
        scanners = []
        
        if self.config.scan_dependencies:
            scanners.append(DependencyScanner(self.config))
        
        if self.config.scan_secrets:
            scanners.append(SecretsScanner(self.config))
            
        if self.config.scan_sql_injection:
            scanners.append(SQLInjectionScanner(self.config))
            
        if self.config.scan_code_injection:
            scanners.append(CodeInjectionScanner(self.config))
            
        if self.config.scan_frameworks:
            scanners.append(FrameworkScanner(self.config))
            
        if self.config.scan_cryptography:
            scanners.append(CryptographyScanner(self.config))
            
        if self.config.scan_authentication:
            scanners.append(AuthenticationScanner(self.config))
            
        if self.config.scan_xss:
            scanners.append(XSSScanner(self.config))
            
        if self.config.scan_configuration:
            scanners.append(ConfigurationScanner(self.config))
            
        return scanners
    
    def scan(self, project_path: Path, **kwargs) -> ScanResult:
        """
        Perform comprehensive security scan of the project.
        
        Args:
            project_path: Path to the project directory to scan
            **kwargs: Additional scan options
            
        Returns:
            ScanResult object containing all found issues
        """
        start_time = time.time()
        project_path = Path(project_path).resolve()
        
        if not project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {project_path}")
        
        print(f"🔍 Starting security scan of {project_path.name}...")
        
        # Discover files to scan
        files_to_scan = self._discover_files(project_path)
        if not files_to_scan:
            print("⚠️  No Python files found to scan")
            return ScanResult(project_path=project_path)
        
        print(f"📁 Found {len(files_to_scan)} files to scan")
        
        # Initialize progress tracking
        total_tasks = len(files_to_scan) * len(self.scanners)
        self.progress_tracker.start(total_tasks)
        
        # Collect all issues
        all_issues = []
        
        try:
            # Run scanners in parallel for each file
            if self.config.parallel_scanning:
                all_issues = self._parallel_scan(files_to_scan)
            else:
                all_issues = self._sequential_scan(files_to_scan)
                
        except KeyboardInterrupt:
            print("\n⚠️  Scan interrupted by user")
            self.progress_tracker.stop()
            raise
        except Exception as e:
            print(f"\n❌ Scan failed with error: {e}")
            self.progress_tracker.stop()
            raise
        finally:
            self.progress_tracker.stop()
        
        # Create scan result
        scan_duration = time.time() - start_time
        result = ScanResult(
            project_path=project_path,
            issues=all_issues,
            configuration=self.config.to_dict()
        )
        result.statistics.scan_duration = scan_duration
        result.statistics.files_scanned = len(files_to_scan)
        
        # Calculate final security score
        result.statistics.calculate_security_score()
        
        # Print summary
        self._print_scan_summary(result)
        
        return result
    
    def _discover_files(self, project_path: Path) -> List[Path]:
        """Discover all Python files to scan."""
        return discover_python_files(
            project_path,
            include_patterns=self.config.include_patterns,
            exclude_patterns=self.config.exclude_patterns,
            follow_symlinks=self.config.follow_symlinks
        )
    
    def _parallel_scan(self, files_to_scan: List[Path]) -> List[SecurityIssue]:
        """Scan files in parallel using thread pool."""
        all_issues = []
        max_workers = min(self.config.max_workers, len(files_to_scan))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            future_to_file = {}
            for file_path in files_to_scan:
                for scanner in self.scanners:
                    future = executor.submit(self._scan_file, scanner, file_path)
                    future_to_file[future] = (scanner.__class__.__name__, file_path)
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                scanner_name, file_path = future_to_file[future]
                try:
                    issues = future.result()
                    all_issues.extend(issues)
                    self.progress_tracker.update(f"{scanner_name}: {file_path.name}")
                except Exception as e:
                    print(f"⚠️  Error scanning {file_path} with {scanner_name}: {e}")
                    self.progress_tracker.update(f"Error: {file_path.name}")
        
        return all_issues
    
    def _sequential_scan(self, files_to_scan: List[Path]) -> List[SecurityIssue]:
        """Scan files sequentially."""
        all_issues = []
        
        for file_path in files_to_scan:
            for scanner in self.scanners:
                try:
                    issues = self._scan_file(scanner, file_path)
                    all_issues.extend(issues)
                    self.progress_tracker.update(f"{scanner.__class__.__name__}: {file_path.name}")
                except Exception as e:
                    print(f"⚠️  Error scanning {file_path} with {scanner.__class__.__name__}: {e}")
                    self.progress_tracker.update(f"Error: {file_path.name}")
        
        return all_issues
    
    def _scan_file(self, scanner: Any, file_path: Path) -> List[SecurityIssue]:
        """Scan a single file with a specific scanner."""
        try:
            return scanner.scan_file(file_path)
        except Exception as e:
            # Log error but don't fail the entire scan
            print(f"⚠️  Scanner {scanner.__class__.__name__} failed on {file_path}: {e}")
            return []
    
    def _print_scan_summary(self, result: ScanResult):
        """Print a summary of the scan results."""
        stats = result.statistics
        
        print("\n" + "="*60)
        print("🔒 SECURITY SCAN SUMMARY")
        print("="*60)
        
        # Security score with emoji
        score = stats.security_score
        if score >= 90:
            score_emoji = "🎉"
            score_message = "Excellent! Your code is very secure!"
        elif score >= 70:
            score_emoji = "👍"
            score_message = "Good security practices detected."
        elif score >= 50:
            score_emoji = "⚠️"
            score_message = "Some security improvements needed."
        else:
            score_emoji = "🚨"
            score_message = "Critical security issues found!"
        
        print(f"{score_emoji} Security Score: {score}/100")
        print(f"   {score_message}")
        print()
        
        # Issue counts by severity
        print("📊 Issues Found:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = stats.issues_by_severity[severity]
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "🟢"}
                print(f"   {emoji[severity.value]} {severity.value.title()}: {count}")
        
        print(f"\n📁 Files scanned: {stats.files_scanned}")
        print(f"📁 Files with issues: {stats.files_with_issues}")
        print(f"⏱️  Scan duration: {stats.scan_duration:.2f}s")
        
        # Top categories
        if stats.total_issues > 0:
            top_categories = sorted(
                stats.issues_by_category.items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]
            
            print(f"\n🔍 Top issue categories:")
            for category, count in top_categories:
                if count > 0:
                    print(f"   • {category.value.replace('_', ' ').title()}: {count}")
        
        print("\n" + "="*60)
        
        # Recommendations
        if stats.total_issues > 0:
            print("💡 Next steps:")
            if stats.issues_by_severity[Severity.CRITICAL] > 0:
                print("   1. Fix critical issues immediately")
            if stats.issues_by_severity[Severity.HIGH] > 0:
                print("   2. Address high-severity issues soon")
            if stats.issues_by_severity[Severity.MEDIUM] > 0:
                print("   3. Plan fixes for medium-severity issues")
            print("   4. Run 'secscan --fix .' to auto-fix safe issues")
            print("   5. Generate detailed report: 'secscan --output html .'")
        else:
            print("🎉 No security issues found! Great job!")
        
        print("="*60)
    
    def quick_scan(self, project_path: Path) -> ScanResult:
        """Perform a quick scan focusing only on critical issues."""
        original_config = self.config
        self.config = SecurityScanConfig(
            scan_dependencies=True,
            scan_secrets=True,
            scan_sql_injection=True,
            scan_code_injection=True,
            scan_frameworks=False,
            scan_cryptography=False,
            scan_authentication=False,
            scan_xss=False,
            scan_configuration=False,
            severity_threshold=Severity.HIGH
        )
        
        try:
            result = self.scan(project_path)
        finally:
            self.config = original_config
        
        return result
    
    def deep_scan(self, project_path: Path) -> ScanResult:
        """Perform a comprehensive deep scan including all checks."""
        # Enable all scanners and lower severity threshold
        self.config.scan_dependencies = True
        self.config.scan_secrets = True
        self.config.scan_sql_injection = True
        self.config.scan_code_injection = True
        self.config.scan_frameworks = True
        self.config.scan_cryptography = True
        self.config.scan_authentication = True
        self.config.scan_xss = True
        self.config.scan_configuration = True
        self.config.severity_threshold = Severity.INFO
        
        return self.scan(project_path)
