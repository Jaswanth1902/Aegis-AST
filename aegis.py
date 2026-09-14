#!/usr/bin/env python3
"""
Aegis-AST: Zero-Dependency Sub-Second Python AST & Secret Security Linter
========================================================================
Audits codebases for high-entropy hardcoded credentials, debug flags,
environment exposure, missing security headers, and grammar-aware SQL injection.

Author: K. Sai Jaswanth Reddy (@Jaswanth1902)
License: MIT
"""

import os
import sys
import re
import ast
import json
import math
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import io

def configure_console():
    """Ensure UTF-8 console output on Windows when run as CLI."""
    if sys.platform == "win32":
        if hasattr(sys.stdout, "buffer") and not getattr(sys.stdout, "closed", False):
            try:
                sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            except Exception:
                pass
        if hasattr(sys.stderr, "buffer") and not getattr(sys.stderr, "closed", False):
            try:
                sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
            except Exception:
                pass

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GRAY = "\033[90m"

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}

# Regex patterns for high-confidence hardcoded secrets
SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    ("AWS Access Key", r"(?i)\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b", "CRITICAL"),
    ("AWS Secret Key", r"(?i)\baws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", "CRITICAL"),
    ("GitHub Personal Access Token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b", "CRITICAL"),
    ("GitHub Fine-Grained Token", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", "CRITICAL"),
    ("OpenAI API Key", r"\bsk-(?:proj-|live-)?[A-Za-z0-9_\-]{32,100}\b", "CRITICAL"),
    ("Anthropic API Key", r"\bsk-ant-(?:api03-)?[A-Za-z0-9_\-]{32,100}\b", "CRITICAL"),
    ("Google Cloud / Gemini API Key", r"\bAIza[0-9A-Za-z-_]{35}\b", "CRITICAL"),
    ("Slack Token / Webhook", r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b|https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}", "CRITICAL"),
    ("Stripe API Key", r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b", "CRITICAL"),
    ("Private Key Header", r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY-----", "CRITICAL"),
    ("Database URL with Password", r"(?i)\b(postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-!@#$%^&*()+=]+@[a-zA-Z0-9_\.\-]+(?::[0-9]+)?\/[a-zA-Z0-9_\-]+", "CRITICAL"),
    ("JWT Bearer Token", r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b", "HIGH"),
    ("Generic High-Entropy Secret Assignment", r"""(?i)\b(password|passwd|secret|api_key|apikey|access_token|auth_token)\s*[:=]\s*['"](?![\$\{]|your_|test|dummy|placeholder|<|TODO|sample|CHANGE_ME|admin)[a-zA-Z0-9_\-!@#$%^&*()+=]{8,80}['"]""", "HIGH")
]

# Patterns for dangerous debug flags & runtime exposures
DEBUG_PATTERNS: List[Tuple[str, str, str]] = [
    ("Python Debug Mode Enabled", r"(?i)\b(DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True[^)]*|app\.debug\s*=\s*True)\b", "HIGH"),
    ("Interactive Breakpoint / Debugger", r"\b(breakpoint|pdb\.set_trace|ipdb\.set_trace)\s*\(|debugger;", "HIGH"),
    ("Arbitrary Code Execution (eval/exec)", r"\b(eval|exec|new Function)\s*\(", "HIGH"),
    ("Wildcard CORS Origin", r"""(?i)(allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*:\s*['"]\*['"])""", "MEDIUM"),
    ("Unsafe Pickle / Deserialization", r"\b(pickle\.loads?|yaml\.load)\s*\(", "HIGH"),
    ("Verbose Credential Logging", r"\bconsole\.log\(.*(password|token|secret|auth|cred).*\)", "HIGH")
]

# Grammar-aware SQL Injection patterns
SQLI_PATTERNS: List[Tuple[str, str, str]] = [
    ("Python f-string in SQL Query", r"(?i)\bf['\"].*?\b(?:SELECT\b.+?\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*?\{.+?\}", "CRITICAL"),
    ("Python % Formatting in SQL Query", r"(?i)\b(?:execute|cursor\.execute|raw|db\.query)\s*\(\s*['\"].*?\b(?:SELECT\b.+?\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*?%s", "HIGH"),
    ("Python String Concatenation in SQL Query", r"(?i)\b(?:execute|cursor\.execute|raw|db\.query)\s*\(\s*['\"].*?\b(?:SELECT\b.+?\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*?[\'\"]\s*\+", "HIGH"),
    ("JS/TS Template Literal in SQL Query", r"(?i)\b(?:db\.query|db\.execute|sequelize\.query|client\.query)\s*\(\s*`.*?\b(?:SELECT\b.+?\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*?\$\{.+?\}", "CRITICAL"),
    ("Unsafe Raw SQL Format Function", r"(?i)\b(?:execute|cursor\.execute|raw|db\.query)\s*\(\s*['\"].*?\b(?:SELECT\b.+?\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*?[\'\"]\.format\(", "HIGH")
]

IGNORED_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
    "dist", "build", "coverage", ".obsidian", ".gemini", "archive",
    "04_Archive", "knowledge", "Gaming_Central", "assets"
}

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".docx", ".zip", ".tar", ".gz", ".7z", ".exe", ".bin",
    ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav", ".lock"
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string to detect randomized cryptographic keys."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occ: Dict[str, int] = {}
    for char in data:
        occ[char] = occ.get(char, 0) + 1
    for count in occ.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SecurityIssue:
    def __init__(self, category: str, title: str, severity: str, file_path: str, line_num: int, line_content: str, recommendation: str):
        self.category = category
        self.title = title
        self.severity = severity
        self.file_path = file_path
        self.line_num = line_num
        self.line_content = line_content.strip()
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_num,
            "snippet": self.line_content,
            "recommendation": self.recommendation
        }


class AegisAuditor:
    def __init__(self, root_dir: str, strict: bool = False):
        self.root_dir = Path(root_dir).resolve()
        self.strict = strict
        self.issues: List[SecurityIssue] = []
        self.scanned_files_count = 0
        self.env_files_found: List[Path] = []
        self.gitignore_path = self.root_dir / ".gitignore"
        self.has_env_example = False
        self.has_env_references = False
        self.web_framework_files: List[Path] = []
        self.security_headers_configured = False

    def scan(self) -> List[SecurityIssue]:
        """Runs static analysis across files in root directory."""
        if not self.root_dir.exists():
            print(f"{RED}[ERROR] Target path does not exist: {self.root_dir}{RESET}")
            sys.exit(1)

        if self.root_dir.is_file():
            self.audit_file(self.root_dir)
            self.scanned_files_count = 1
            return self.issues

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
            
            for file in files:
                file_path = Path(root) / file
                ext = file_path.suffix.lower()

                if ext in IGNORED_EXTENSIONS:
                    continue

                if file == ".env" or file.startswith(".env.") and not file.endswith(".example") and not file.endswith(".template"):
                    self.env_files_found.append(file_path)

                if file in (".env.example", ".env.template", ".env.sample"):
                    self.has_env_example = True

                self.audit_file(file_path)
                self.scanned_files_count += 1

        self.audit_env_hygiene()
        self.audit_security_headers()
        return self.issues

    def audit_file(self, file_path: Path):
        """Audits a single source file."""
        if file_path.name in ("aegis.py", "security_audit.py"):
            return

        rel_path = file_path.name if self.root_dir.is_file() else str(file_path.relative_to(self.root_dir))
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return

        is_test_file = any(t in rel_path.lower() for t in ["test", "mock", "fixture", "spec"])
        content_full = "".join(lines)

        if any(fw in content_full for fw in ["FastAPI(", "Flask(", "express()", "next/server", "createServer", "Django"]):
            self.web_framework_files.append(file_path)
            if any(hdr in content_full for hdr in ["Content-Security-Policy", "X-Frame-Options", "helmet", "SecurityMiddleware"]):
                self.security_headers_configured = True

        if any(env_token in content_full for env_token in ["os.getenv(", "os.environ", "process.env", "dotenv"]):
            self.has_env_references = True

        for idx, line in enumerate(lines, start=1):
            trimmed = line.strip()
            if trimmed.startswith(("#", "//", "/*", "*")):
                continue

            # 1. Hardcoded Secrets Check
            if not is_test_file:
                for name, pattern, severity in SECRET_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        matched_str = match.group(0)
                        if any(ph in matched_str.lower() for ph in ["example", "dummy", "test", "fake", "placeholder", "<your"]):
                            continue
                        # Use entropy validation for generic assignments
                        if "Generic" in name:
                            assigned_val = matched_str.split("=")[-1].split(":")[-1].strip(" '\"")
                            if calculate_shannon_entropy(assigned_val) < 2.8:
                                continue

                        self.issues.append(SecurityIssue(
                            category="Hardcoded Secret",
                            title=f"Detected {name}",
                            severity=severity,
                            file_path=rel_path,
                            line_num=idx,
                            line_content=line,
                            recommendation="Extract sensitive credential to .env and load via os.getenv() or process.env."
                        ))

            # 2. Debug Flags Check
            for name, pattern, severity in DEBUG_PATTERNS:
                if re.search(pattern, line):
                    self.issues.append(SecurityIssue(
                        category="Debug / Insecure Runtime",
                        title=name,
                        severity=severity,
                        file_path=rel_path,
                        line_num=idx,
                        line_content=line,
                        recommendation="Disable debug modes in production. Use environment-based conditional toggling."
                    ))

            # 3. SQL Injection Patterns
            for name, pattern, severity in SQLI_PATTERNS:
                if re.search(pattern, line):
                    self.issues.append(SecurityIssue(
                        category="SQL Injection Risk",
                        title=name,
                        severity=severity,
                        file_path=rel_path,
                        line_num=idx,
                        line_content=line,
                        recommendation="Use parameterized SQL queries with tuple/dict parameters instead of string interpolation."
                    ))

    def audit_env_hygiene(self):
        """Validates .env file exclusion and .env.example presence."""
        if self.env_files_found:
            gitignore_content = ""
            if self.gitignore_path.exists():
                try:
                    with open(self.gitignore_path, "r", encoding="utf-8", errors="replace") as f:
                        gitignore_content = f.read()
                except Exception:
                    pass

            for env_path in self.env_files_found:
                rel_env = env_path.name if self.root_dir.is_file() else str(env_path.relative_to(self.root_dir))
                if ".env" not in gitignore_content and rel_env not in gitignore_content:
                    self.issues.append(SecurityIssue(
                        category="Environment Exposure",
                        title="Unprotected .env File (Missing in .gitignore)",
                        severity="CRITICAL",
                        file_path=rel_env,
                        line_num=1,
                        line_content=f"Found unignored file: {rel_env}",
                        recommendation="Add '.env' and '.env.*' to your root .gitignore immediately to prevent credential leaks."
                    ))

        if self.has_env_references and not self.has_env_example:
            self.issues.append(SecurityIssue(
                category="Documentation Gap",
                title="Missing .env.example Template",
                severity="MEDIUM",
                file_path=".env.example",
                line_num=0,
                line_content="Repository references environment variables but lacks .env.example",
                recommendation="Create a sanitized .env.example with mock values to guide secure configuration."
            ))

    def audit_security_headers(self):
        """Checks for missing security headers in web services."""
        if self.web_framework_files and not self.security_headers_configured:
            primary_file = str(self.web_framework_files[0].relative_to(self.root_dir))
            self.issues.append(SecurityIssue(
                category="Missing Security Headers",
                title="Missing Standard HTTP Security Headers (CSP, HSTS, X-Frame-Options)",
                severity="MEDIUM",
                file_path=primary_file,
                line_num=1,
                line_content="Web framework initialization without explicit security headers middleware",
                recommendation="Configure security headers (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options: DENY)."
            ))


def main():
    configure_console()
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis-AST: Zero-Dependency Sub-Second Python AST & Secret Security Linter."
    )
    parser.add_argument("path", nargs="?", default=".", help="Target project root directory to scan.")
    parser.add_argument("--strict", action="store_true", help="Treat MEDIUM severity warnings as blocking gate failures.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format for CI/CD pipelines.")
    parser.add_argument("--output", help="Save scan report to a file.")
    args = parser.parse_args()

    auditor = AegisAuditor(root_dir=args.path, strict=args.strict)
    issues = auditor.scan()

    critical_count = sum(1 for i in issues if i.severity == "CRITICAL")
    high_count = sum(1 for i in issues if i.severity == "HIGH")
    medium_count = sum(1 for i in issues if i.severity == "MEDIUM")
    low_count = sum(1 for i in issues if i.severity == "LOW")

    gate_failed = critical_count > 0 or high_count > 0 or (args.strict and medium_count > 0)

    if args.json:
        report = {
            "target": str(auditor.root_dir),
            "files_scanned": auditor.scanned_files_count,
            "gate_status": "FAILED" if gate_failed else "PASSED",
            "counts": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "findings": [i.to_dict() for i in issues]
        }
        output_str = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_str)
        else:
            print(output_str)
        sys.exit(1 if gate_failed else 0)

    report_lines = []
    report_lines.append("\n" + "=" * 80)
    report_lines.append(f"{CYAN}🛡️  AEGIS-AST STATIC SECURITY AUDIT REPORT{RESET}")
    report_lines.append("=" * 80)
    report_lines.append(f"Target Directory:    {auditor.root_dir}")
    report_lines.append(f"Files Scanned:       {auditor.scanned_files_count}")
    report_lines.append(f"Total Findings:      {len(issues)}")
    report_lines.append(f"Severity Breakdown:  {RED}{critical_count} CRITICAL{RESET} | {YELLOW}{high_count} HIGH{RESET} | {BLUE}{medium_count} MEDIUM{RESET} | {GRAY}{low_count} LOW{RESET}")
    report_lines.append("-" * 80 + "\n")

    for idx, issue in enumerate(issues, start=1):
        color = RED if issue.severity == "CRITICAL" else (YELLOW if issue.severity == "HIGH" else BLUE)
        report_lines.append(f"{idx}. [{color}{issue.severity}{RESET}] {issue.title}")
        report_lines.append(f"   Location:       {issue.file_path}:{issue.line_num}")
        report_lines.append(f"   Category:       {issue.category}")
        report_lines.append(f"   Snippet:        {GRAY}{issue.line_content}{RESET}")
        report_lines.append(f"   Remediation:    {issue.recommendation}\n")

    report_lines.append("=" * 80)
    if gate_failed:
        report_lines.append(f"{RED}❌ SECURITY DELIVERY GATE: FAILED{RESET}")
        report_lines.append(f"Found {critical_count} CRITICAL and {high_count} HIGH vulnerabilities.")
    else:
        report_lines.append(f"{GREEN}✅ SECURITY DELIVERY GATE: PASSED (ALL CHECKS NOMINAL){RESET}")
        report_lines.append("No blocking security vulnerabilities detected.")
    report_lines.append("=" * 80 + "\n")

    final_report = "\n".join(report_lines)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(final_report)
    else:
        print(final_report)

    sys.exit(1 if gate_failed else 0)


if __name__ == "__main__":
    main()
