"""
Unit Tests for PromptManager
"""

from prompts.prompt_manager import PromptManager


def test_prompt_manager_loads_all_templates():
    pm = PromptManager()
    assert "vulnerability_hunter" in pm._cache
    assert "security_auditor" in pm._cache
    assert "patch_synthesizer" in pm._cache


def test_hunter_prompt_compilation():
    pm = PromptManager()
    meta = pm.get_prompt_metadata("vulnerability_hunter")
    assert meta["version"] == "1.2.0"

    compiled = pm.compile_hunter_prompt(
        file_path="test.py",
        code_content="def foo(): pass",
        ast_metadata={"functions": {"foo": {}}, "classes": [], "dangerous_sinks": [], "sanitizers": []},
    )
    assert "system_instruction" in compiled
    assert "CodePulse Hunter" in compiled["system_instruction"]
    assert "test.py" in compiled["user_prompt"]
