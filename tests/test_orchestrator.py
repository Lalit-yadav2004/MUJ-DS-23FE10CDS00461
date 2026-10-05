"""
Unit Tests for AgentOrchestrator
"""

from src.agents.orchestrator import AgentOrchestrator
from src.config import load_settings


def test_orchestrator_mock_vulnerable_flow():
    settings = load_settings()
    settings.llm.default_provider = "mock"

    orchestrator = AgentOrchestrator(settings)
    sample_code = """
def run_command(host):
    import os
    os.system(f"ping {host}")
"""
    report = orchestrator.analyze_file("vulnerable.py", code_content=sample_code, force_refresh=True)

    assert report.file_path == "vulnerable.py"
    assert len(report.hunter_candidates) >= 1
    assert len(report.audited_findings) >= 1
    assert report.overall_status in ("VULNERABILITIES_CONFIRMED", "PATCHES_VALIDATED", "PATCH_FAILURES")
    assert len(report.patches) >= 1
    assert len(report.telemetry) == 4  # Hunter, Auditor, Patcher, Validator


def test_orchestrator_mock_false_positive_elimination():
    settings = load_settings()
    settings.llm.default_provider = "mock"

    orchestrator = AgentOrchestrator(settings)
    # This code uses a REAL defensive pattern: parameterized query with placeholder
    # The mock auditor should correctly detect it as a false positive
    sample_code = """
def get_user(db, raw_id):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (raw_id,))
    return cursor.fetchone()
"""
    report = orchestrator.analyze_file("safe.py", code_content=sample_code, force_refresh=True)

    assert report.file_path == "safe.py"
    # Auditor should have rejected the candidate — parameterized query is the explicit defense
    assert any(f.verdict == "REJECTED_FALSE_POSITIVE" for f in report.audited_findings)
    assert report.summary_statistics["false_positives_eliminated"] >= 1
    assert len(report.patches) == 0
