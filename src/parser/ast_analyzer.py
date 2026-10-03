"""
CodePulse AI - AST-Guided Semantic Parser
=========================================
Extracts Abstract Syntax Tree (AST) representations, function hierarchies,
dangerous API sinks, and defensive sanitizers from source files.
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# Dangerous execution sinks that indicate potential vulnerabilities
DANGEROUS_SINKS = {
    "sql": ["execute", "executemany", "raw", "select", "fetch"],
    "command": ["system", "popen", "run", "Popen", "call", "check_output", "check_call"],
    "deserialization": ["loads", "load"],  # pickle, yaml, marshal
    "filesystem": ["open", "remove", "unlink", "rmdir", "rmtree", "copyfile"],
    "eval": ["eval", "exec", "__import__", "compile"],
    "network": ["get", "post", "put", "delete", "request", "urlopen"],
}

# Defensive sanitizer and validation indicators
DEFENSIVE_PATTERNS = {
    "casting": ["int", "float", "bool", "UUID", "str"],
    "escaping": ["quote", "escape", "shlex.quote", "html.escape", "quote_plus"],
    "path_bounding": ["basename", "abspath", "realpath", "commonpath", "resolve"],
    "type_checks": ["isinstance", "issubclass"],
}


@dataclass
class FunctionSignature:
    name: str
    args: List[str]
    start_line: int
    end_line: int
    docstring: Optional[str] = None
    calls: List[str] = field(default_factory=list)


@dataclass
class CodeStructure:
    file_path: str
    language: str
    total_lines: int
    functions: Dict[str, FunctionSignature] = field(default_factory=dict)
    classes: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    dangerous_sinks: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    raw_content: str = ""

    def to_metadata_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "language": self.language,
            "total_lines": self.total_lines,
            "functions": {
                name: {
                    "args": fn.args,
                    "start_line": fn.start_line,
                    "end_line": fn.end_line,
                    "calls": fn.calls,
                }
                for name, fn in self.functions.items()
            },
            "classes": self.classes,
            "imports": self.imports,
            "dangerous_sinks": self.dangerous_sinks,
            "sanitizers": self.sanitizers,
        }


class ASTVisitor(ast.NodeVisitor):
    """Walks the AST tree to extract structural signatures and sink/sanitizer patterns."""

    def __init__(self):
        self.functions: Dict[str, FunctionSignature] = {}
        self.classes: List[str] = []
        self.imports: List[str] = []
        self.dangerous_sinks: Set[str] = set()
        self.sanitizers: Set[str] = set()
        self._current_function: Optional[FunctionSignature] = None

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            self.imports.append(f"{mod}.{alias.name}")
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.classes.append(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        args = [arg.arg for arg in node.args.args]
        doc = ast.get_docstring(node)
        end_line = getattr(node, "end_lineno", node.lineno)
        fn_sig = FunctionSignature(
            name=node.name,
            args=args,
            start_line=node.lineno,
            end_line=end_line,
            docstring=doc,
        )
        self.functions[node.name] = fn_sig
        prev_fn = self._current_function
        self._current_function = fn_sig
        self.generic_visit(node)
        self._current_function = prev_fn

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_call_name(node.func)
        if func_name:
            if self._current_function:
                self._current_function.calls.append(func_name)

            # Check dangerous sinks
            for category, sinks in DANGEROUS_SINKS.items():
                for s in sinks:
                    if func_name == s or func_name.endswith(f".{s}"):
                        self.dangerous_sinks.add(f"{func_name} (Line {node.lineno}, Category: {category})")

            # Check sanitizers & defenses
            for cat, guards in DEFENSIVE_PATTERNS.items():
                for g in guards:
                    if func_name == g or func_name.endswith(f".{g}"):
                        self.sanitizers.add(f"{func_name} (Line {node.lineno}, Guard: {cat})")

        self.generic_visit(node)

    def _resolve_call_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._resolve_call_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return None


class ASTAnalyzer:
    """High-level analyzer that converts source files into CodeStructure metadata."""

    @staticmethod
    def analyze_file(file_path: str, content: Optional[str] = None) -> CodeStructure:
        p = Path(file_path)
        ext = p.suffix.lower()

        if content is None:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

        total_lines = len(content.splitlines())

        if ext == ".py":
            return ASTAnalyzer._analyze_python(file_path, content, total_lines)
        else:
            return ASTAnalyzer._analyze_generic(file_path, content, ext, total_lines)

    @staticmethod
    def _analyze_python(file_path: str, content: str, total_lines: int) -> CodeStructure:
        try:
            tree = ast.parse(content, filename=file_path)
            visitor = ASTVisitor()
            visitor.visit(tree)

            return CodeStructure(
                file_path=file_path,
                language="python",
                total_lines=total_lines,
                functions=visitor.functions,
                classes=visitor.classes,
                imports=visitor.imports,
                dangerous_sinks=sorted(list(visitor.dangerous_sinks)),
                sanitizers=sorted(list(visitor.sanitizers)),
                raw_content=content,
            )
        except SyntaxError:
            # Fallback to regex analysis if Python file has syntax error
            return ASTAnalyzer._analyze_generic(file_path, content, ".py", total_lines)

    @staticmethod
    def _analyze_generic(file_path: str, content: str, ext: str, total_lines: int) -> CodeStructure:
        """Lightweight regex token/pattern scanner for JS/TS/Go or invalid Python."""
        funcs = {}
        sinks = []
        sanitizers = []

        # Simple function regex
        fn_pattern = re.compile(r"(?:function|def|func)\s+([a-zA-Z_0-9]+)\s*\((.*?)\)", re.MULTILINE)
        for i, match in enumerate(fn_pattern.finditer(content)):
            fn_name = match.group(1)
            raw_args = [a.strip() for a in match.group(2).split(",") if a.strip()]
            line_no = content[: match.start()].count("\n") + 1
            funcs[fn_name] = FunctionSignature(
                name=fn_name,
                args=raw_args,
                start_line=line_no,
                end_line=line_no + 10,
            )

        # Keyword matching
        for category, target_sinks in DANGEROUS_SINKS.items():
            for s in target_sinks:
                for line_idx, line in enumerate(content.splitlines(), start=1):
                    if re.search(rf"\b{s}\b", line):
                        sinks.append(f"{s} (Line {line_idx}, Category: {category})")

        return CodeStructure(
            file_path=file_path,
            language="generic" if ext != ".py" else "python",
            total_lines=total_lines,
            functions=funcs,
            classes=[],
            imports=[],
            dangerous_sinks=sinks[:15],
            sanitizers=sanitizers,
            raw_content=content,
        )
