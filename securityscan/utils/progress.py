"""
Progress tracking utilities for SecurityScan.
"""

import sys
import time
from typing import Optional


class ProgressTracker:
    """
    Simple progress tracker for terminal output.
    """
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.total = 0
        self.current = 0
        self.start_time = None
        self.last_update = 0
        self.current_task = ""
        
    def start(self, total: int):
        """Start tracking progress."""
        if not self.enabled:
            return
            
        self.total = total
        self.current = 0
        self.start_time = time.time()
        self.last_update = time.time()
        
        if total > 0:
            print(f"📊 Progress: 0/{total} (0%)", end='', flush=True)
    
    def update(self, task: str = "", increment: int = 1):
        """Update progress."""
        if not self.enabled:
            return
            
        self.current += increment
        self.current_task = task
        
        # Throttle updates to avoid flickering
        now = time.time()
        if now - self.last_update < 0.1:  # Update max every 100ms
            return
        
        self.last_update = now
        
        if self.total > 0:
            percentage = (self.current / self.total) * 100
            elapsed = now - self.start_time if self.start_time else 0
            
            # Calculate ETA
            eta = ""
            if self.current > 0 and elapsed > 0:
                rate = self.current / elapsed
                remaining = (self.total - self.current) / rate if rate > 0 else 0
                eta = f", ETA: {remaining:.1f}s"
            
            # Clear line and update
            print(f"\r📊 Progress: {self.current}/{self.total} ({percentage:.1f}%){eta}", end='', flush=True)
            
            if task:
                print(f" - {task}", end='', flush=True)
    
    def stop(self):
        """Stop tracking progress."""
        if not self.enabled:
            return
            
        if self.total > 0:
            elapsed = time.time() - self.start_time if self.start_time else 0
            print(f"\r✅ Completed: {self.current}/{self.total} in {elapsed:.1f}s")
        else:
            print()  # New line


class Spinner:
    """
    Simple spinner for long-running operations.
    """
    
    def __init__(self, message: str = "Processing..."):
        self.message = message
        self.spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self.current_char = 0
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the spinner."""
        import threading
        
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self, final_message: str = ""):
        """Stop the spinner."""
        self.running = False
        if self.thread:
            self.thread.join()
        
        # Clear spinner line
        print(f"\r{' ' * (len(self.message) + 3)}", end='', flush=True)
        print(f"\r{final_message}", flush=True)
    
    def _spin(self):
        """Spinner animation loop."""
        while self.running:
            char = self.spinner_chars[self.current_char]
            print(f"\r{char} {self.message}", end='', flush=True)
            self.current_char = (self.current_char + 1) % len(self.spinner_chars)
            time.sleep(0.1)


class ProgressBar:
    """
    Rich progress bar for detailed progress tracking.
    """
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self.width = 50
        
    def update(self, increment: int = 1, description: str = ""):
        """Update progress bar."""
        self.current += increment
        if description:
            self.description = description
        
        # Calculate progress
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        filled = int((self.current / self.total) * self.width) if self.total > 0 else 0
        
        # Create progress bar
        bar = "█" * filled + "░" * (self.width - filled)
        
        # Calculate ETA
        elapsed = time.time() - self.start_time
        eta = ""
        if self.current > 0 and elapsed > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            eta = f" ETA: {remaining:.1f}s"
        
        # Print progress
        print(f"\r{self.description}: [{bar}] {percentage:.1f}% ({self.current}/{self.total}){eta}", 
              end='', flush=True)
    
    def finish(self, message: str = "Complete"):
        """Finish progress bar."""
        elapsed = time.time() - self.start_time
        print(f"\r{message}: [{self.total}/{self.total}] 100.0% in {elapsed:.1f}s", flush=True)


def print_status(message: str, status: str = "info"):
    """
    Print a status message with appropriate formatting.
    
    Args:
        message: Status message
        status: Status type (info, success, warning, error)
    """
    status_icons = {
        "info": "ℹ️ ",
        "success": "✅",
        "warning": "⚠️ ",
        "error": "❌",
    }
    
    icon = status_icons.get(status, "ℹ️ ")
    print(f"{icon} {message}")


def print_section_header(title: str):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"🔍 {title}")
    print(f"{'='*60}")


def print_subsection_header(title: str):
    """Print a subsection header."""
    print(f"\n📋 {title}")
    print("-" * 40)
