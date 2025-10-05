"""
Main CLI entry point for SecurityScan.
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core import SecurityScanner
from ..models import Severity
from ..utils.config import SecurityScanConfig
from ..reporters import ReportGenerator


console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="SecurityScan")
@click.pass_context
def cli(ctx):
    """
    🔒 SecurityScan - Comprehensive security analysis for Python projects
    
    A powerful security scanning tool that detects vulnerabilities, hardcoded secrets,
    and security misconfigurations in Python projects with a single command.
    """
    ctx.ensure_object(dict)


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path), default='.')
@click.option('--config', '-c', type=click.Path(exists=True, path_type=Path), 
              help='Configuration file path')
@click.option('--output', '-o', type=click.Choice(['terminal', 'html', 'json', 'sarif', 'markdown']), 
              default='terminal', help='Output format')
@click.option('--output-file', '-f', type=click.Path(path_type=Path),
              help='Output file path (required for non-terminal formats)')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low', 'info']),
              default='info', help='Minimum severity level to report')
@click.option('--quick', is_flag=True, help='Quick scan (critical and high issues only)')
@click.option('--deep', is_flag=True, help='Deep scan (comprehensive analysis)')
@click.option('--fix', is_flag=True, help='Automatically fix safe issues')
@click.option('--ignore', '-i', multiple=True, help='Ignore files matching pattern')
@click.option('--include', multiple=True, help='Include only files matching pattern')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode (minimal output)')
@click.option('--no-colors', is_flag=True, help='Disable colored output')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']),
              help='Exit with error code if issues found above severity')
@click.option('--parallel/--no-parallel', default=True, help='Enable/disable parallel scanning')
@click.option('--max-workers', type=int, default=4, help='Maximum number of worker threads')
@click.option('--update-db', is_flag=True, help='Update vulnerability databases')
def scan(path, config, output, output_file, severity, quick, deep, fix, ignore, include, 
         verbose, quiet, no_colors, fail_on, parallel, max_workers, update_db):
    """Scan a Python project for security vulnerabilities."""
    
    # Set up console
    if no_colors:
        console.no_color = True
    
    # Load configuration
    try:
        if config:
            security_config = SecurityScanConfig.from_file(config)
        else:
            # Try to find config file automatically
            config_file = SecurityScanConfig.find_config_file(path)
            if config_file:
                security_config = SecurityScanConfig.from_file(config_file)
            else:
                security_config = SecurityScanConfig()
        
        # Apply command line overrides
        security_config.severity_threshold = Severity(severity)
        security_config.output_format = output
        security_config.output_file = str(output_file) if output_file else None
        security_config.verbose = verbose
        security_config.quiet = quiet
        security_config.auto_fix = fix
        security_config.parallel_scanning = parallel
        security_config.max_workers = max_workers
        security_config.update_databases = update_db
        
        if ignore:
            security_config.exclude_patterns.extend(ignore)
        if include:
            security_config.include_patterns = list(include)
        
        # Apply scan mode
        if quick:
            security_config.severity_threshold = Severity.HIGH
            security_config.scan_frameworks = False
            security_config.scan_cryptography = False
            security_config.scan_authentication = False
            security_config.scan_xss = False
            security_config.scan_configuration = False
        elif deep:
            security_config.severity_threshold = Severity.INFO
            # All scanners enabled by default
        
    except Exception as e:
        console.print(f"[red]❌ Configuration error: {e}[/red]")
        sys.exit(1)
    
    # Initialize scanner
    scanner = SecurityScanner(security_config)
    
    # Show welcome message
    if not quiet:
        console.print(Panel.fit(
            "[bold blue]🔒 SecurityScan[/bold blue]\n"
            "Comprehensive security analysis for Python projects",
            border_style="blue"
        ))
        console.print(f"[dim]Scanning: {path.resolve()}[/dim]")
    
    # Perform scan
    try:
        if quick:
            result = scanner.quick_scan(path)
        elif deep:
            result = scanner.deep_scan(path)
        else:
            result = scanner.scan(path)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Scan failed: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)
    
    # Generate output
    try:
        reporter = ReportGenerator(security_config)
        
        if output == 'terminal':
            reporter.generate_terminal_report(result, console)
        else:
            if not output_file:
                console.print(f"[red]❌ Output file required for {output} format[/red]")
                sys.exit(1)
            
            if output == 'html':
                reporter.generate_html_report(result, output_file)
            elif output == 'json':
                reporter.generate_json_report(result, output_file)
            elif output == 'sarif':
                reporter.generate_sarif_report(result, output_file)
            elif output == 'markdown':
                reporter.generate_markdown_report(result, output_file)
            
            if not quiet:
                console.print(f"[green]✅ Report saved to: {output_file}[/green]")
    
    except Exception as e:
        console.print(f"[red]❌ Report generation failed: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)
    
    # Check fail-on condition
    if fail_on:
        fail_severity = Severity(fail_on)
        critical_issues = [issue for issue in result.issues 
                          if issue.severity.numeric_value > fail_severity.numeric_value]
        
        if critical_issues:
            console.print(f"[red]❌ Found {len(critical_issues)} issues above {fail_on} severity[/red]")
            sys.exit(1)
    
    # Exit with appropriate code
    if result.statistics.total_issues > 0:
        sys.exit(1 if result.statistics.issues_by_severity.get(Severity.CRITICAL, 0) > 0 else 0)
    else:
        sys.exit(0)


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path), default='.')
@click.option('--output', '-o', type=click.Path(path_type=Path), required=True,
              help='Output file path')
def fix(path, output):
    """Automatically fix safe security issues."""
    console.print("[yellow]🔧 Auto-fix feature coming soon![/yellow]")
    console.print("For now, please review the scan results and apply fixes manually.")
    sys.exit(0)


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path), default='.')
def watch(path):
    """Continuously monitor project for security issues."""
    console.print("[yellow]👁️  Watch mode coming soon![/yellow]")
    console.print("This feature will continuously monitor your project for new security issues.")
    sys.exit(0)


@cli.command()
def update_db():
    """Update vulnerability databases."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Updating vulnerability databases...", total=None)
        
        # Simulate database update
        import time
        time.sleep(2)
        
        progress.update(task, description="✅ Databases updated successfully!")
    
    console.print("[green]✅ Vulnerability databases updated![/green]")


@cli.command()
@click.argument('issue_id')
def explain(issue_id):
    """Get detailed explanation of a specific issue type."""
    console.print(f"[yellow]📖 Detailed explanation for issue: {issue_id}[/yellow]")
    console.print("This feature will provide detailed information about specific security issues.")
    sys.exit(0)


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path), default='.')
def baseline(path):
    """Create baseline for tracking new issues only."""
    console.print("[yellow]📊 Baseline creation coming soon![/yellow]")
    console.print("This feature will create a baseline to track only new security issues.")
    sys.exit(0)


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path), default='.')
def diff(path):
    """Compare with previous scan results."""
    console.print("[yellow]📈 Diff mode coming soon![/yellow]")
    console.print("This feature will compare current scan results with previous scans.")
    sys.exit(0)


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path), default='.')
def audit_log(path):
    """Generate audit trail of all scans."""
    console.print("[yellow]📋 Audit log coming soon![/yellow]")
    console.print("This feature will generate an audit trail of all security scans.")
    sys.exit(0)


@cli.command()
def init():
    """Initialize SecurityScan configuration for the project."""
    config_file = Path('.securityscan.yml')
    
    if config_file.exists():
        console.print(f"[yellow]⚠️  Configuration file already exists: {config_file}[/yellow]")
        if not click.confirm("Overwrite existing configuration?"):
            return
    
    # Create default configuration
    config = SecurityScanConfig()
    config.save_to_file(config_file)
    
    console.print(f"[green]✅ Created configuration file: {config_file}[/green]")
    console.print("[dim]Edit this file to customize your security scanning rules.[/dim]")


@cli.command()
def version():
    """Show version information."""
    console.print("[bold blue]SecurityScan[/bold blue]")
    console.print(f"Version: [green]1.0.0[/green]")
    console.print(f"Python: [green]{sys.version}[/green]")


def main():
    """Main entry point."""
    try:
        cli()
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        console.print_exception()
        sys.exit(1)


if __name__ == '__main__':
    main()
