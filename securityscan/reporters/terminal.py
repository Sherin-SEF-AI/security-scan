"""
Terminal output reporter for SecurityScan.
"""

from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax

from ..models import ScanResult, Severity, IssueCategory


class TerminalReporter:
    """Terminal-based report generator."""
    
    def __init__(self, config):
        self.config = config
    
    def generate_report(self, result: ScanResult, console: Console):
        """Generate terminal report."""
        if self.config.quiet:
            self._generate_quiet_report(result, console)
        else:
            self._generate_detailed_report(result, console)
    
    def _generate_quiet_report(self, result: ScanResult, console: Console):
        """Generate minimal report for quiet mode."""
        stats = result.statistics
        
        if stats.total_issues == 0:
            console.print("✅ No security issues found")
            return
        
        # Show only critical and high issues
        critical_issues = result.get_issues_by_severity(Severity.CRITICAL)
        high_issues = result.get_issues_by_severity(Severity.HIGH)
        
        if critical_issues:
            console.print(f"🔴 {len(critical_issues)} critical issues")
        if high_issues:
            console.print(f"🟠 {len(high_issues)} high issues")
        
        console.print(f"Security Score: {stats.security_score}/100")
    
    def _generate_detailed_report(self, result: ScanResult, console: Console):
        """Generate detailed terminal report."""
        stats = result.statistics
        
        # Summary panel
        self._print_summary_panel(result, console)
        
        # Issues by severity
        if stats.total_issues > 0:
            self._print_issues_table(result, console)
            
            # Show detailed issues
            self._print_detailed_issues(result, console)
        else:
            console.print(Panel.fit(
                "[bold green]🎉 No security issues found![/bold green]\n"
                "Your code looks secure!",
                border_style="green"
            ))
    
    def _print_summary_panel(self, result: ScanResult, console: Console):
        """Print summary panel with key statistics."""
        stats = result.statistics
        
        # Security score with emoji
        score = stats.security_score
        if score >= 90:
            score_emoji = "🎉"
            score_color = "green"
            score_message = "Excellent! Your code is very secure!"
        elif score >= 70:
            score_emoji = "👍"
            score_color = "green"
            score_message = "Good security practices detected."
        elif score >= 50:
            score_emoji = "⚠️"
            score_color = "yellow"
            score_message = "Some security improvements needed."
        else:
            score_emoji = "🚨"
            score_color = "red"
            score_message = "Critical security issues found!"
        
        # Create summary text
        summary_text = f"{score_emoji} [bold {score_color}]Security Score: {score}/100[/bold {score_color}]\n"
        summary_text += f"   {score_message}\n\n"
        
        summary_text += f"📊 [bold]Issues Found:[/bold] {stats.total_issues}\n"
        summary_text += f"📁 [bold]Files Scanned:[/bold] {stats.files_scanned}\n"
        summary_text += f"📁 [bold]Files with Issues:[/bold] {stats.files_with_issues}\n"
        summary_text += f"⏱️  [bold]Scan Duration:[/bold] {stats.scan_duration:.2f}s"
        
        console.print(Panel(
            summary_text,
            title="🔒 Security Scan Summary",
            border_style="blue"
        ))
    
    def _print_issues_table(self, result: ScanResult, console: Console):
        """Print table of issues by severity."""
        stats = result.statistics
        
        table = Table(title="📊 Issues by Severity")
        table.add_column("Severity", style="bold", no_wrap=True)
        table.add_column("Count", justify="right")
        table.add_column("Percentage", justify="right")
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = stats.issues_by_severity[severity]
            if count > 0:
                percentage = (count / stats.total_issues) * 100
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "🟢"}
                severity_text = f"{emoji[severity.value]} {severity.value.title()}"
                table.add_row(severity_text, str(count), f"{percentage:.1f}%")
        
        console.print(table)
        
        # Top categories
        if stats.total_issues > 0:
            top_categories = sorted(
                stats.issues_by_category.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            category_table = Table(title="🔍 Top Issue Categories")
            category_table.add_column("Category", style="bold")
            category_table.add_column("Count", justify="right")
            
            for category, count in top_categories:
                if count > 0:
                    category_name = category.value.replace('_', ' ').title()
                    category_table.add_row(category_name, str(count))
            
            console.print(category_table)
    
    def _print_detailed_issues(self, result: ScanResult, console: Console):
        """Print detailed issues grouped by severity."""
        # Group issues by severity
        issues_by_severity = {}
        for issue in result.issues:
            if issue.severity not in issues_by_severity:
                issues_by_severity[issue.severity] = []
            issues_by_severity[issue.severity].append(issue)
        
        # Print issues by severity (critical first)
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity in issues_by_severity:
                issues = issues_by_severity[severity]
                self._print_issues_for_severity(severity, issues, console)
    
    def _print_issues_for_severity(self, severity: Severity, issues: list, console: Console):
        """Print all issues for a specific severity level."""
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "🟢"}
        severity_emoji = emoji[severity.value]
        severity_title = f"{severity_emoji} {severity.value.title()} Issues ({len(issues)})"
        
        console.print(f"\n[bold]{severity_title}[/bold]")
        console.print("=" * len(severity_title))
        
        # Group issues by file
        issues_by_file = {}
        for issue in issues:
            file_path = issue.file_path
            if file_path not in issues_by_file:
                issues_by_file[file_path] = []
            issues_by_file[file_path].append(issue)
        
        # Print issues grouped by file
        for file_path, file_issues in issues_by_file.items():
            console.print(f"\n[bold cyan]📁 {file_path}[/bold cyan]")
            
            for issue in file_issues:
                self._print_single_issue(issue, console)
    
    def _print_single_issue(self, issue, console: Console):
        """Print a single security issue."""
        # Issue header
        console.print(f"\n[bold yellow]⚠️  {issue.title}[/bold yellow]")
        console.print(f"[dim]Line {issue.line_number}, Column {issue.column_number}[/dim]")
        
        # Issue description
        console.print(f"[white]{issue.description}[/white]")
        
        # Code snippet
        if issue.code_snippet:
            console.print("\n[bold]Code:[/bold]")
            try:
                syntax = Syntax(
                    issue.code_snippet,
                    "python",
                    theme="monokai",
                    line_numbers=True,
                    start_line=max(1, issue.line_number - 3)
                )
                console.print(syntax)
            except Exception:
                # Fallback to plain text if syntax highlighting fails
                console.print(f"[dim]{issue.code_snippet}[/dim]")
        
        # Fix suggestion
        if issue.fix_suggestion:
            console.print(f"\n[bold green]💡 Fix:[/bold green] {issue.fix_suggestion}")
        
        # References
        if issue.references:
            console.print(f"\n[bold blue]📚 References:[/bold blue]")
            for ref in issue.references[:3]:  # Show max 3 references
                console.print(f"  • {ref}")
        
        # Tags
        if issue.tags:
            tags_text = " ".join([f"[dim]#{tag}[/dim]" for tag in sorted(issue.tags)])
            console.print(f"\n[dim]Tags: {tags_text}[/dim]")
        
        console.print()  # Empty line for spacing
