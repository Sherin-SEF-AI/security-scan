"""
Report generators for SecurityScan.
"""

from .terminal import TerminalReporter
from .html import HTMLReporter
from .json import JSONReporter
from .sarif import SARIFReporter
from .markdown import MarkdownReporter


class ReportGenerator:
    """Main report generator that delegates to specific reporters."""
    
    def __init__(self, config):
        self.config = config
        self.terminal_reporter = TerminalReporter(config)
        self.html_reporter = HTMLReporter(config)
        self.json_reporter = JSONReporter(config)
        self.sarif_reporter = SARIFReporter(config)
        self.markdown_reporter = MarkdownReporter(config)
    
    def generate_terminal_report(self, result, console):
        """Generate terminal report."""
        self.terminal_reporter.generate_report(result, console)
    
    def generate_html_report(self, result, output_file):
        """Generate HTML report."""
        self.html_reporter.generate_report(result, output_file)
    
    def generate_json_report(self, result, output_file):
        """Generate JSON report."""
        self.json_reporter.generate_report(result, output_file)
    
    def generate_sarif_report(self, result, output_file):
        """Generate SARIF report."""
        self.sarif_reporter.generate_report(result, output_file)
    
    def generate_markdown_report(self, result, output_file):
        """Generate Markdown report."""
        self.markdown_reporter.generate_report(result, output_file)


__all__ = ["ReportGenerator"]