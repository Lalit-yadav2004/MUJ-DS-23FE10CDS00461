"""
CodePulse AI - AST-Guided Semantic Parser (Multi-Language: Python & C/C++)
===========================================================================
Extracts Abstract Syntax Tree (AST) representations, function hierarchies,
dangerous API sinks, and defensive sanitizers from Python and C/C++ source files.
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# Dangerous execution sinks that indicate potential vulnerabilities
DANGEROUS_SINKS = {
    # Python & C/C++ SQL sinks
    "sql": ["execute", "executemany", "raw", "select", "fetch"],
    # OS Command execution
    "command": [
        "system", "popen", "run", "Popen", "call", "check_output", "check_call",
        "exec", "execl", "execlp", "execle", "execv", "execvp"
    ],
    # Python Deserialization
    "deserialization": ["loads", "load"],  # pickle, yaml, marshal
    # Filesystem operations
    "filesystem": ["open", "remove", "unlink", "rmdir", "rmtree", "copyfile", "fopen", "remove"],
    # Code evaluation
    "eval": ["eval", "exec", "__import__", "compile"],
    # C/C++ Buffer Overflow & Unsafe String Operations (CWE-120, CWE-121)
    "buffer_overflow": [
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
        "memcpy", "memmove", "strncpy", "strncat"
    ],
    # C/C++ Format String Vulnerabilities (CWE-134)
    "format_string": ["printf", "fprintf", "sprintf", "vprintf", "vfprintf", "syslog"],
    # C/C++ Memory Management (CWE-416, CWE-401)
    "memory_management": ["free", "delete", "malloc", "calloc", "realloc"],
    # Network operations
    "network": ["get", "post", "put", "delete", "request", "urlopen"],
}

# Defensive sanitizer and validation indicators
DEFENSIVE_PATTERNS = {
    "casting": ["int", "float", "bool", "UUID", "str", "static_cast", "dynamic_cast", "reinterpret_cast"],
    "escaping": ["quote", "escape", "shlex.quote", "html.escape", "quote_plus"],
    "path_bounding": ["basename", "abspath", "realpath", "commonpath", "resolve", "std::filesystem::canonical"],
    "bounds_checking": [
        "sizeof", "strlen", "snprintf", "strncpy_s", "strncat_s",
        "std::string", "std::vector", "std::array", "std::span", "std::string_view"
    ],
    "smart_pointers": ["std::unique_ptr", "std::shared_ptr", "std::make_unique", "std::make_shared"],
    "safe_io": ["std::cout", "std::cin", "std::format", "std::print"],
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
    """Walks Python AST tree to extract structural signatures and sink/sanitizer patterns."""

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
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            val_name = ""
            if isinstance(node.func.value, ast.Name):
                val_name = node.func.value.id
            call_name = f"{val_name}.{node.func.attr}" if val_name else node.func.attr

        if call_name and self._current_function:
            self._current_function.calls.append(call_name)

        # Check against dangerous sink list
        for category, sink_list in DANGEROUS_SINKS.items():
            for target_sink in sink_list:
                if call_name == target_sink or call_name.endswith(f".{target_sink}"):
                    self.dangerous_sinks.add(
                        f"{call_name} (Line {node.lineno}, Category: {category})"
                    )

        # Check against sanitizers
        for category, san_list in DEFENSIVE_PATTERNS.items():
            for target_san in san_list:
                if call_name == target_san or call_name.endswith(f".{target_san}"):
                    self.sanitizers.add(
                        f"{call_name} (Line {node.lineno}, Defense: {category})"
                    )

        self.generic_visit(node)


class ASTAnalyzer:
    """High-level multi-language analyzer (Python, C, C++, etc.)."""

    CPP_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}

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
        elif ext in ASTAnalyzer.CPP_EXTENSIONS:
            return ASTAnalyzer._analyze_cpp(file_path, content, ext, total_lines)
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
            return ASTAnalyzer._analyze_generic(file_path, content, ".py", total_lines)

    @staticmethod
    def _analyze_cpp(file_path: str, content: str, ext: str, total_lines: int) -> CodeStructure:
        """C & C++ semantic analyzer: extracts functions, includes, classes, memory/overflow sinks."""
        funcs = {}
        sinks = []
        sanitizers = []
        imports = []
        classes = []

        lines = content.splitlines()

        # 1. Extract #include directives
        for line in lines:
            inc_match = re.match(r'^\s*#\s*include\s*([<"][^>"]+[>"])', line)
            if inc_match:
                imports.append(inc_match.group(1))

        # 2. Extract class and struct definitions
        for line in lines:
            cls_match = re.match(r'^\s*(?:class|struct)\s+([a-zA-Z_0-9]+)', line)
            if cls_match:
                classes.append(cls_match.group(1))

        # 3. Extract C/C++ function signatures
        # Matches: void func(char* str), int main(int argc, char** argv), std::string get_data()
        cpp_fn_pattern = re.compile(
            r'^\s*(?:[a-zA-Z_0-9:<>\*&]+\s+)+([a-zA-Z_0-9]+)\s*\(([^)]*)\)\s*(?:const)?\s*\{',
            re.MULTILINE
        )
        for match in cpp_fn_pattern.finditer(content):
            fn_name = match.group(1)
            # Filter out control structures
            if fn_name in ("if", "for", "while", "switch", "catch"):
                continue
            raw_args = [a.strip() for a in match.group(2).split(",") if a.strip()]
            line_no = content[: match.start()].count("\n") + 1
            funcs[fn_name] = FunctionSignature(
                name=fn_name,
                args=raw_args,
                start_line=line_no,
                end_line=min(total_lines, line_no + 20),
            )

        # 4. Extract C/C++ Dangerous Sinks with accurate line numbers
        for category, target_sinks in DANGEROUS_SINKS.items():
            for s in target_sinks:
                # Word boundary match for function calls: strcpy(...) or system(...)
                pat = re.compile(rf"\b{s}\s*\(", re.MULTILINE)
                for line_idx, line in enumerate(lines, start=1):
                    # Skip comment lines
                    trimmed = line.strip()
                    if trimmed.startswith("//") or trimmed.startswith("/*"):
                        continue
                    if pat.search(line):
                        sinks.append(f"{s} (Line {line_idx}, Category: {category})")

        # 5. Extract C/C++ Defensive Sanitizers
        for category, san_list in DEFENSIVE_PATTERNS.items():
            for target_san in san_list:
                for line_idx, line in enumerate(lines, start=1):
                    if target_san in line:
                        sanitizers.append(f"{target_san} (Line {line_idx}, Defense: {category})")

        lang = "c" if ext == ".c" else "cpp"

        return CodeStructure(
            file_path=file_path,
            language=lang,
            total_lines=total_lines,
            functions=funcs,
            classes=classes,
            imports=imports,
            dangerous_sinks=sinks[:25],
            sanitizers=sanitizers[:25],
            raw_content=content,
        )

    @staticmethod
    def _analyze_generic(file_path: str, content: str, ext: str, total_lines: int) -> CodeStructure:
        """Lightweight regex token/pattern scanner for JS/TS/Go or generic code."""
        funcs = {}
        sinks = []
        sanitizers = []

        fn_pattern = re.compile(r"(?:function|def|func)\s+([a-zA-Z_0-9]+)\s*\((.*?)\)", re.MULTILINE)
        for match in fn_pattern.finditer(content):
            fn_name = match.group(1)
            raw_args = [a.strip() for a in match.group(2).split(",") if a.strip()]
            line_no = content[: match.start()].count("\n") + 1
            funcs[fn_name] = FunctionSignature(
                name=fn_name,
                args=raw_args,
                start_line=line_no,
                end_line=line_no + 10,
            )

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
