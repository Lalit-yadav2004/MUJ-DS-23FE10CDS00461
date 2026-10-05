"""
Unit Tests for PatchValidatorAgent (Stage 4)
"""

from src.agents.validator import PatchValidatorAgent
from src.agents.schemas import PatchProposal


def test_validator_passes_valid_patch():
    validator = PatchValidatorAgent()
    orig_code = """
def authenticate(cursor, username, password):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
"""
    patch = PatchProposal(
        candidate_id="CAND-001",
        cwe_id="CWE-89",
        file_path="auth.py",
        patch_summary="Use parameterized query",
        unified_diff="--- a/auth.py\n+++ b/auth.py\n",
        patched_code="""
def authenticate(cursor, username, password):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
""",
        security_rationale="Parameterized query bounds parameter",
        regression_test_code="""
def test_safe(mock_cursor):
    authenticate(mock_cursor, "admin", "pass")
    assert mock_cursor.execute.called
""",
    )

    results, telemetry = validator.validate_patches([patch], orig_code)
    assert len(results) == 1
    assert results[0].verdict == "PASS"
    assert results[0].regenerate is False
    assert results[0].checks["syntax_valid"] is True
    assert results[0].checks["sink_neutralized"] is True
    assert results[0].checks["safe_replacement_exists"] is True
    assert results[0].checks["signatures_intact"] is True
    assert results[0].checks["no_new_sinks"] is True


def test_validator_fails_syntax_error():
    validator = PatchValidatorAgent()
    orig_code = "def foo(): pass"
    patch = PatchProposal(
        candidate_id="CAND-001",
        cwe_id="CWE-89",
        file_path="auth.py",
        patch_summary="Syntax broken",
        unified_diff="",
        patched_code="def foo( incomplete",
        security_rationale="test",
        regression_test_code="def test(): pass",
    )

    results, _ = validator.validate_patches([patch], orig_code)
    assert results[0].verdict == "FAIL"
    assert results[0].regenerate is True
    assert results[0].checks["syntax_valid"] is False
