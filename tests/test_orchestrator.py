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
    assert report.overall_status == "VULNERABILITIES_CONFIRMED"
    assert len(report.patches) >= 1
    assert len(report.telemetry) == 3


def test_orchestrator_mock_false_positive_elimination():
    settings = load_settings()
    settings.llm.default_provider = "mock"

    orchestrator = AgentOrchestrator(settings)
    sample_code = """
def get_user(db, raw_id):
    clean_id = int(raw_id)
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {clean_id}")
    return cursor.fetchone()
"""
    report = orchestrator.analyze_file("safe.py", code_content=sample_code, force_refresh=True)

    assert report.file_path == "safe.py"
    # Auditor should have rejected the candidate because of int() casting
    assert any(f.verdict == "REJECTED_FALSE_POSITIVE" for f in report.audited_findings)
    assert report.summary_statistics["false_positives_eliminated"] >= 1
    assert len(report.patches) == 0
