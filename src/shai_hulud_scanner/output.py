"""Output formatting and logging utilities."""

from __future__ import annotations

import sys
from typing import Optional

# Global debug flag
DEBUG = False


def set_debug(enabled: bool):
    global DEBUG
    DEBUG = enabled


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    NC = '\033[0m'


def log_info(msg: str):
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {msg}", file=sys.stderr)


def log_error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}", file=sys.stderr)


def log_warn(msg: str):
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}", file=sys.stderr)


def log_progress(index: int, total: int, msg: str):
    pct = (index / total) * 100 if total > 0 else 0
    print(f"{Colors.CYAN}[SCAN]{Colors.NC} ({index}/{total}) {pct:5.1f}% | {msg}", file=sys.stderr)


def log_debug(msg: str):
    if DEBUG:
        print(f"{Colors.DIM}[DEBUG]{Colors.NC} {msg}", file=sys.stderr)


def log_detection(
    lib: str,
    version: str,
    repo: str,
    file: str,
    url: str,
    matched_lines: Optional[list[tuple[int, str]]] = None
):
    """Log a detection. matched_lines is a list of (line_number, line_content) tuples."""
    print(f"{Colors.RED}{Colors.BOLD}[🚨 DETECTION]{Colors.NC} {lib}@{version}", file=sys.stderr)
    print(f"           Repository: {Colors.YELLOW}{repo}{Colors.NC}", file=sys.stderr)
    print(f"           File:       {file}", file=sys.stderr)

    # Add line number to URL if we have matched lines
    display_url = url
    if matched_lines and len(matched_lines) > 0:
        first_line = matched_lines[0][0]
        # GitHub URL format: add #L<line_number> anchor
        display_url = f"{url}#L{first_line}"

    print(f"           URL:        {display_url}", file=sys.stderr)

    if DEBUG and matched_lines:
        print(f"           {Colors.MAGENTA}Matched lines:{Colors.NC}", file=sys.stderr)
        for line_no, content in matched_lines[:5]:  # Show up to 5 matched lines
            print(
                f"             {Colors.CYAN}{line_no:>5}{Colors.NC}: {Colors.DIM}{content.strip()}{Colors.NC}",
                file=sys.stderr
            )
    print("", file=sys.stderr)


def print_header(org: str, total_libs: int, concurrency: int, output_file: str):
    print("")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.BOLD}  SHAI-HULUD SCANNER{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  Organization:    {Colors.CYAN}{org}{Colors.NC}")
    print(f"  Libraries:       {Colors.CYAN}{total_libs}{Colors.NC}")
    print(f"  Concurrency:     {Colors.CYAN}{concurrency}{Colors.NC}")
    print(f"  Output:          {Colors.CYAN}{output_file}{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print("")


def print_summary(report, detection_count: int):
    print("")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.BOLD}  SCAN COMPLETE{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  Libraries Scanned:      {Colors.CYAN}{report.total_libraries_scanned}{Colors.NC}")
    print(f"  Total Detections:       {Colors.RED}{Colors.BOLD}{detection_count}{Colors.NC}")
    print(f"  Affected Repositories:  {Colors.RED}{Colors.BOLD}{report.affected_repositories}{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")

    if report.affected_repositories > 0:
        print("")
        print(f"{Colors.BOLD}Affected Repositories:{Colors.NC}")
        for repo in report.results:
            lib_count = len(repo['affected_libraries'])
            print(f"  ⚠️  {repo['repository']} - {lib_count} compromised package(s)")

    print("")
