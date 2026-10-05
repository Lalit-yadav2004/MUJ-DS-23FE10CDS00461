"""
Unit Tests for C and C++ Semantic AST Analysis
"""

from src.parser.ast_analyzer import ASTAnalyzer


def test_cpp_analyzer_detects_functions_includes_classes():
    cpp_code = """
#include <iostream>
#include <cstring>
#include "my_header.h"

class AuthHandler {
public:
    void login(const char* user, const char* pass) {
        char buf[32];
        strcpy(buf, user);
    }
};

int main(int argc, char** argv) {
    printf(argv[1]);
    system("ls -la");
    return 0;
}
"""
    struct = ASTAnalyzer.analyze_file("auth.cpp", content=cpp_code)
    assert struct.language == "cpp"
    assert "<iostream>" in struct.imports
    assert "<cstring>" in struct.imports
    assert '"my_header.h"' in struct.imports
    assert "AuthHandler" in struct.classes
    assert "login" in struct.functions or "main" in struct.functions

    # Check sinks detected
    sinks_str = " ".join(struct.dangerous_sinks)
    assert "strcpy" in sinks_str
    assert "printf" in sinks_str
    assert "system" in sinks_str


def test_cpp_analyzer_detects_c_file():
    c_code = """
#include <stdio.h>
#include <stdlib.h>

void execute_task(char* input) {
    char cmd[128];
    sprintf(cmd, "run.sh %s", input);
    system(cmd);
}
"""
    struct = ASTAnalyzer.analyze_file("task.c", content=c_code)
    assert struct.language == "c"
    sinks_str = " ".join(struct.dangerous_sinks)
    assert "sprintf" in sinks_str
    assert "system" in sinks_str
