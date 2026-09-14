"""
Unit Tests for Aegis-AST Static Security Linter
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis import AegisAuditor, calculate_shannon_entropy


def test_shannon_entropy_calculation():
    """Validates entropy calculation for low vs high entropy strings."""
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    
    # High entropy randomized key
    entropy_high = calculate_shannon_entropy("ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ")
    assert entropy_high > 3.5

    # Repetitive test string
    entropy_low = calculate_shannon_entropy("passwordpassword")
    assert entropy_low < 3.0


def test_aws_and_github_secret_detection():
    """Ensures real high-confidence AWS and GitHub PAT tokens are detected as CRITICAL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        bad_file = tmp_path / "creds.py"
        bad_file.write_text("""
AWS_KEY = "AKIA1234567890ABCDEF"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
""", encoding="utf-8")

        auditor = AegisAuditor(root_dir=str(tmp_path))
        issues = auditor.scan()

        criticals = [i for i in issues if i.severity == "CRITICAL"]
        assert len(criticals) >= 2
        titles = [i.title for i in criticals]
        assert "Detected AWS Access Key" in titles
        assert "Detected GitHub Personal Access Token" in titles


def test_grammar_aware_sql_injection_detection():
    """Validates that real SQL injection is flagged, but normal English sentences are ignored."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        
        # Insecure query
        vuln_file = tmp_path / "db.py"
        vuln_file.write_text("""
def get_user(uid):
    query = f"SELECT * FROM users WHERE id = '{uid}'"
    return query
""", encoding="utf-8")

        # Benign file with English words 'from' and 'where'
        safe_file = tmp_path / "safe.py"
        safe_file.write_text("""
def log_status(path, destination):
    print(f"Loaded config from {path} where destination is {destination}")
""", encoding="utf-8")

        auditor = AegisAuditor(root_dir=str(tmp_path))
        issues = auditor.scan()

        sqli_issues = [i for i in issues if i.category == "SQL Injection Risk"]
        assert len(sqli_issues) == 1
        assert sqli_issues[0].file_path == "db.py"


def test_debug_and_eval_detection():
    """Checks detection of eval() and interactive breakpoints."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        debug_file = tmp_path / "app.py"
        debug_file.write_text("""
DEBUG = True
eval("import os; os.system('ls')")
breakpoint()
""", encoding="utf-8")

        auditor = AegisAuditor(root_dir=str(tmp_path))
        issues = auditor.scan()

        debug_issues = [i for i in issues if i.category == "Debug / Insecure Runtime"]
        assert len(debug_issues) >= 3


def test_unprotected_env_file_missing_in_gitignore():
    """Verifies that an unignored .env file is flagged as CRITICAL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgres://localhost:5432\n", encoding="utf-8")

        auditor = AegisAuditor(root_dir=str(tmp_path))
        issues = auditor.scan()

        env_issues = [i for i in issues if i.category == "Environment Exposure"]
        assert len(env_issues) == 1
        assert "Unprotected .env File" in env_issues[0].title


def test_clean_project_passes_delivery_gate():
    """Validates that a clean codebase passes with zero issues."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        clean_file = tmp_path / "main.py"
        clean_file.write_text("""
import sys

def add(a: int, b: int) -> int:
    return a + b

if __name__ == '__main__':
    print(add(2, 3))
""", encoding="utf-8")

        auditor = AegisAuditor(root_dir=str(tmp_path))
        issues = auditor.scan()
        assert len(issues) == 0
