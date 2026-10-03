"""
Unit Tests for ASTAnalyzer
"""

from src.parser.ast_analyzer import ASTAnalyzer


def test_ast_python_analyzer_detects_functions_and_sinks():
    sample_code = """
import os

def vulnerable_exec(user_input):
    cmd = f"echo {user_input}"
    os.system(cmd)
    return True
"""
    structure = ASTAnalyzer.analyze_file("sample.py", content=sample_code)

    assert structure.language == "python"
    assert "vulnerable_exec" in structure.functions
    assert "user_input" in structure.functions["vulnerable_exec"].args
    assert any("os.system" in s for s in structure.dangerous_sinks)


def test_ast_detects_sanitizers():
    sample_code = """
import shlex

def clean_command(cmd_arg):
    safe = shlex.quote(cmd_arg)
    num = int(cmd_arg)
    return safe
"""
    structure = ASTAnalyzer.analyze_file("clean.py", content=sample_code)

    assert any("shlex.quote" in s for s in structure.sanitizers)
    assert any("int" in s for s in structure.sanitizers)
