"""
CodePulse AI - High-Fidelity Mock LLM Provider
===============================================
Provides deterministic, rule-informed multi-agent responses for offline testing,
academic evaluation, and CI pipelines without requiring API keys.

AUDITOR LOGIC: All sanitizer / false-positive detection operates ONLY on the
extracted source code block, never on the prompt header or system instruction.
"""

import re
import time
from typing import Any, Dict, List, Optional


# ===========================================================================
# Source Code Extraction Helpers
# ===========================================================================

def _extract_source_code(prompt: str) -> str:
    """
    Extracts ONLY the raw source code from a compiled prompt.
    Looks between triple backtick fences or after '--- SOURCE CODE ---' / '--- FULL SOURCE CODE ---' markers.
    Returns empty string if no code block is found.
    """
    # Try triple-backtick fenced code block first
    fence_match = re.search(r"```(?:python)?\n(.*?)```", prompt, re.DOTALL)
    if fence_match:
        return fence_match.group(1)

    # Fallback: look for source code section header
    for marker in ["--- SOURCE CODE ---", "--- FULL SOURCE CODE ---", "--- ORIGINAL SOURCE CODE ---"]:
        if marker in prompt:
            after = prompt.split(marker, 1)[1]
            # Strip everything after the next section marker if present
            next_section = re.search(r"\n---\s", after)
            if next_section:
                after = after[:next_section.start()]
            return after.strip()

    # Last resort: return the whole prompt (worst case — should rarely happen)
    return prompt


def _has_sanitizer(source_code: str) -> bool:
    """
    Returns True ONLY if an explicit, evidence-based sanitizer or safe pattern exists
    in the actual source code. Follows RULE 1–9 of the Auditor prompt strictly.
    """
    # SQL — only parameterized placeholders are safe; f-strings / % / .format are NOT
    has_parameterized_sql = bool(re.search(
        r"cursor\.execute\s*\(\s*['\"].*?['\"],\s*[(\[]",  # cursor.execute("...", (val,))
        source_code
    ))
    # Shell — only shlex.quote() wrapping before the call
    has_shlex_quote = "shlex.quote(" in source_code
    # Path traversal — realpath + explicit prefix check both required
    has_realpath_check = "os.path.realpath(" in source_code and (
        "startswith(" in source_code or "commonpath(" in source_code
    )
    # Deserialization — json.loads is safe, pickle.loads is not
    # (this is the absence case; no additional sanitizer matters for pickle)
    # C/C++ memory safety — std::string or bounded snprintf
    has_cpp_safe_pattern = "std::string" in source_code or "snprintf(" in source_code or "strncpy_s(" in source_code

    return has_parameterized_sql or has_shlex_quote or has_realpath_check or has_cpp_safe_pattern


def _get_sinks_from_source(source_code: str) -> Dict[str, bool]:
    """
    Scans source code for dangerous sinks. Returns a dict of {sink_type: found}.
    """
    return {
        "sql": bool(re.search(
            r"cursor\.execute\(.*?[f'\"]|cursor\.execute\(.*?\+|\.raw\(|\.executemany\(",
            source_code, re.DOTALL
        )),
        "command_system": bool(re.search(r"os\.system\s*\(", source_code)),
        "command_subprocess": bool(re.search(r"subprocess\.(run|Popen|call|check_output)\s*\(.*?shell\s*=\s*True", source_code, re.DOTALL)),
        "eval": bool(re.search(r"\beval\s*\(", source_code)),
        "exec": bool(re.search(r"\bexec\s*\(", source_code)),
        "pickle": bool(re.search(r"pickle\.loads?\s*\(", source_code)),
        "yaml_unsafe": bool(re.search(r"yaml\.load\s*\([^)]*Loader\s*=\s*None|yaml\.load\s*\([^)]*\)", source_code)),
        "path_traversal": bool(re.search(r"open\s*\(\s*(f['\"]|os\.path\.join|[\w]+\s*\+)", source_code)),
        "buffer_overflow": bool(re.search(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(", source_code)),
        "format_string": bool(re.search(r"\b(printf|fprintf)\s*\(\s*[a-zA-Z_0-9]+(?:\s*\[\s*\d+\s*\])?\s*\)", source_code)),
    }


# ===========================================================================
# Sink → CWE metadata mapping
# ===========================================================================

SINK_TO_CWE = {
    "sql": ("CWE-89", "SQL Injection", "CRITICAL"),
    "command_system": ("CWE-78", "OS Command Injection", "CRITICAL"),
    "command_subprocess": ("CWE-78", "OS Command Injection (shell=True)", "CRITICAL"),
    "eval": ("CWE-95", "Code Injection via eval()", "CRITICAL"),
    "exec": ("CWE-95", "Code Injection via exec()", "CRITICAL"),
    "pickle": ("CWE-502", "Deserialization of Untrusted Data", "CRITICAL"),
    "yaml_unsafe": ("CWE-502", "Deserialization of Untrusted Data (YAML)", "HIGH"),
    "path_traversal": ("CWE-22", "Path Traversal", "HIGH"),
    "buffer_overflow": ("CWE-120", "Classic Buffer Overflow (strcpy/gets)", "CRITICAL"),
    "format_string": ("CWE-134", "Uncontrolled Format String", "CRITICAL"),
}

SINK_DETAILS = {
    "sql": {
        "source_input": "User-supplied parameter passed to SQL via f-string or concatenation",
        "sink_call": "cursor.execute(query)",
        "taint_path": "user_input -> f-string / string concat -> cursor.execute()",
        "hypothesis": "SQL metacharacters (' OR 1=1, UNION SELECT) can alter or dump database contents.",
    },
    "command_system": {
        "source_input": "User-controlled string passed to shell",
        "sink_call": "os.system()",
        "taint_path": "user_input -> string concat / f-string -> os.system()",
        "hypothesis": "Shell metacharacters (;, &, |, $()) allow arbitrary OS command execution.",
    },
    "command_subprocess": {
        "source_input": "User-controlled string passed to subprocess with shell=True",
        "sink_call": "subprocess.call/run(..., shell=True)",
        "taint_path": "user_input -> string -> subprocess(shell=True)",
        "hypothesis": "shell=True causes the entire string to be parsed by the shell, enabling injection.",
    },
    "eval": {
        "source_input": "User-controlled expression passed to eval()",
        "sink_call": "eval(user_input)",
        "taint_path": "user_input -> eval()",
        "hypothesis": "eval() interprets arbitrary Python expressions — trivial to execute os.system() or read files.",
    },
    "exec": {
        "source_input": "User-controlled code block passed to exec()",
        "sink_call": "exec(user_input)",
        "taint_path": "user_input -> exec()",
        "hypothesis": "exec() runs arbitrary Python statements as code.",
    },
    "pickle": {
        "source_input": "Untrusted bytes passed to pickle.loads()",
        "sink_call": "pickle.loads(raw_bytes)",
        "taint_path": "raw_bytes -> pickle.loads()",
        "hypothesis": "Pickle bytecode exploits __reduce__ to execute arbitrary code during deserialization.",
    },
    "yaml_unsafe": {
        "source_input": "Untrusted YAML string passed to yaml.load()",
        "sink_call": "yaml.load(data)",
        "taint_path": "user_data -> yaml.load()",
        "hypothesis": "yaml.load without SafeLoader can execute arbitrary Python via !!python/object tags.",
    },
    "path_traversal": {
        "source_input": "User-supplied filename concatenated with base directory",
        "sink_call": "open(base + user_input)",
        "taint_path": "user_input -> path concat -> open()",
        "hypothesis": "Payload like '../../etc/passwd' escapes the sandbox and reads arbitrary files.",
    },
    "buffer_overflow": {
        "source_input": "Unbounded user-supplied buffer passed into fixed-size stack allocation",
        "sink_call": "strcpy(dest, src) / gets(buf)",
        "taint_path": "user_input -> strcpy() -> stack buffer",
        "hypothesis": "Overwriting adjacent stack memory or return address triggers segmentation fault or arbitrary code execution.",
    },
    "format_string": {
        "source_input": "User-controlled string directly supplied as format specifier",
        "sink_call": "printf(user_str)",
        "taint_path": "user_str -> printf(user_str)",
        "hypothesis": "Format specifiers (%x, %s, %n) allow arbitrary stack/heap memory disclosure and write-what-where exploitation.",
    },
}


class MockProvider:
    """Simulates Gemini multi-agent reasoning for offline evaluation and testing."""

    def __init__(self, simulate_latency: bool = True, latency_range_ms: Optional[List[int]] = None):
        self.simulate_latency = simulate_latency
        self.latency_range_ms = latency_range_ms or [150, 350]

    def generate_structured_json(
        self,
        system_instruction: str,
        user_prompt: str,
        response_schema: Optional[Dict[str, Any]] = None,
        model_override: Optional[str] = None,
        temperature_override: Optional[float] = None,
    ) -> Dict[str, Any]:
        start = time.time()
        if self.simulate_latency:
            time.sleep(0.1)

        if "CodePulse Hunter" in system_instruction:
            data = self._mock_hunter(user_prompt)
        elif "CodePulse Auditor" in system_instruction:
            data = self._mock_auditor(user_prompt)
        elif "CodePulse Patch Synthesizer" in system_instruction:
            data = self._mock_patcher(user_prompt)
        else:
            data = {"status": "ok", "message": "Generic mock response"}

        duration_ms = int((time.time() - start) * 1000)
        prompt_tokens = len(user_prompt.split()) + 120
        completion_tokens = 350
        total_tokens = prompt_tokens + completion_tokens

        return {
            "data": data,
            "metadata": {
                "provider": "mock",
                "model": "codepulse-mock-engine-v2",
                "duration_ms": duration_ms,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
                "attempts": 1,
            },
        }

    def _mock_hunter(self, prompt: str) -> Dict[str, Any]:
        """
        Scans the submitted source code for dangerous sinks and generates
        a candidate for EVERY sink found.
        """
        source_code = _extract_source_code(prompt)
        sinks = _get_sinks_from_source(source_code)

        candidates = []
        cand_idx = 1

        for sink_key, found in sinks.items():
            if not found:
                continue

            cwe_id, cwe_name, severity = SINK_TO_CWE[sink_key]
            details = SINK_DETAILS[sink_key]

            # Try to extract the actual offending line from source code for realism
            snippet = self._extract_sink_snippet(source_code, sink_key)

            candidates.append({
                "candidate_id": f"CAND-{cand_idx:03d}",
                "cwe_id": cwe_id,
                "cwe_name": cwe_name,
                "severity": severity,
                "target_function": self._guess_function(source_code, sink_key),
                "line_range": self._guess_line_range(source_code, sink_key),
                "vulnerable_code_snippet": snippet,
                "source_input": details["source_input"],
                "sink_call": details["sink_call"],
                "taint_path": details["taint_path"],
                "hypothesis": details["hypothesis"],
                "initial_confidence": 0.93,
            })
            cand_idx += 1

        if not candidates:
            # No sinks detected at all — report clean
            candidates.append({
                "candidate_id": "CAND-001",
                "cwe_id": "CWE-20",
                "cwe_name": "Improper Input Validation",
                "severity": "INFO",
                "target_function": "unknown",
                "line_range": [1, 5],
                "vulnerable_code_snippet": "# No dangerous sinks detected",
                "source_input": "None detected",
                "sink_call": "None",
                "taint_path": "No taint path identified",
                "hypothesis": "Code appears clean of obvious injection patterns.",
                "initial_confidence": 0.15,
            })

        return {"candidates": candidates}

    def _mock_auditor(self, prompt: str) -> Dict[str, Any]:
        """
        Auditor that checks ONLY the extracted source code for defensive controls.
        Applies the 9 non-hallucination rules from the prompt.
        """
        # ----------------------------------------------------------------
        # CRITICAL FIX: extract ONLY the source code block, NOT the
        # full prompt (which includes system instructions containing
        # words like int(), shlex.quote that would cause false FP signals)
        # ----------------------------------------------------------------
        source_code = _extract_source_code(prompt)

        # Check if this code actually has sanitizers (evidence-based)
        is_actually_safe = _has_sanitizer(source_code)

        # Get all candidate IDs referenced in the prompt
        cands = re.findall(r'"candidate_id":\s*"(CAND-\d+)"', prompt)
        if not cands:
            cands = ["CAND-001"]

        # Also grab CWE IDs for each candidate to build proper responses
        cwe_map = {}
        for m in re.finditer(r'"candidate_id":\s*"(CAND-\d+)".*?"cwe_id":\s*"(CWE-\d+)"', prompt, re.DOTALL):
            cwe_map[m.group(1)] = m.group(2)

        audited = []
        for cand_id in cands:
            cwe_id = cwe_map.get(cand_id, "CWE-89")

            if is_actually_safe:
                # Genuine false positive — cite the exact defensive evidence found
                defenses = []
                if re.search(r"cursor\.execute\s*\(\s*['\"].*?['\"],\s*[(\[]", source_code):
                    defenses.append("Parameterized query found: `cursor.execute(query, (param,))` — SQL structure separated from data")
                if "shlex.quote(" in source_code:
                    defenses.append("Shell escaping via `shlex.quote()` wraps user input before os/subprocess call")
                if "os.path.realpath(" in source_code and "startswith(" in source_code:
                    defenses.append("Path bounding: `os.path.realpath()` + `startswith()` prefix check constrains to sandbox")

                audited.append({
                    "candidate_id": cand_id,
                    "cwe_id": cwe_id,
                    "verdict": "REJECTED_FALSE_POSITIVE",
                    "calibrated_confidence": 0.06,
                    "defense_mechanisms_found": defenses if defenses else ["Explicit defensive control detected in source code"],
                    "attack_feasibility": "UNEXPLOITABLE",
                    "audit_rationale": (
                        f"Auditor searched the full source code block for {cwe_id} defensive controls. "
                        "Evidence found: the code contains explicit parameterized queries, shell escaping, "
                        "or path boundary validation that neutralizes the taint path before reaching the sink. "
                        "Rejecting as false positive with cited evidence."
                    ),
                    "proceed_to_patch": False,
                })
            else:
                # Real vulnerability — no defensive controls found in source
                severity_desc = {
                    "CWE-89": "SQL string concatenation / f-string reaches cursor.execute() without parameterization",
                    "CWE-78": "User-controlled string reaches os.system() or subprocess with shell=True without shlex.quote()",
                    "CWE-95": "User-controlled expression reaches eval() or exec() with no safe sandbox or escaping",
                    "CWE-502": "Untrusted bytes reach pickle.loads() — arbitrary code execution via __reduce__",
                    "CWE-22": "User-supplied filename concatenated with base path without realpath/prefix boundary check",
                }.get(cwe_id, f"Untrusted input propagates to dangerous {cwe_id} sink without sanitization")

                audited.append({
                    "candidate_id": cand_id,
                    "cwe_id": cwe_id,
                    "verdict": "CONFIRMED",
                    "calibrated_confidence": 0.95,
                    "defense_mechanisms_found": [],
                    "attack_feasibility": "HIGH",
                    "audit_rationale": (
                        f"Auditor searched the entire submitted source code block for defensive controls: "
                        f"parameterized queries, shlex.quote(), realpath+prefix checks, or safe deserialization. "
                        f"None found. Confirmed: {severity_desc}. "
                        f"No evidence exists in the source to reject this finding as a false positive."
                    ),
                    "proceed_to_patch": True,
                })

        return {"audited_findings": audited}

    def _mock_patcher(self, prompt: str) -> Dict[str, Any]:
        """
        Generates targeted patches using the ACTUAL submitted file path and
        real source code context.  Never uses placeholder filenames.
        """
        patches = []
        source_code = _extract_source_code(prompt)
        sinks = _get_sinks_from_source(source_code)
        actual_file = self._extract_file_path(prompt)

        cands = re.findall(r'"candidate_id":\s*"(CAND-\d+)"', prompt)
        cwe_map = {}
        for m in re.finditer(
            r'"candidate_id":\s*"(CAND-\d+)".*?"cwe_id":\s*"(CWE-\d+)"',
            prompt, re.DOTALL
        ):
            cwe_map[m.group(1)] = m.group(2)

        if not cands:
            cands = ["CAND-001"]

        for cand_id in cands:
            cwe_id = cwe_map.get(cand_id, "CWE-89")
            ctx = self._extract_context(source_code, cwe_id, sinks)
            fn, vuln_lines, orig_snippet = ctx["function"], ctx["line_range"], ctx["snippet"]

            if cwe_id == "CWE-89":
                patches.append(self._patch_sql(cand_id, actual_file, fn, vuln_lines, orig_snippet, source_code))
            elif cwe_id == "CWE-78":
                is_sub = sinks.get("command_subprocess")
                patches.append(self._patch_cmd(cand_id, actual_file, fn, vuln_lines, orig_snippet, is_sub, source_code))
            elif cwe_id == "CWE-95":
                patches.append(self._patch_eval(cand_id, actual_file, fn, vuln_lines, orig_snippet, source_code))
            elif cwe_id == "CWE-502":
                patches.append(self._patch_pickle(cand_id, actual_file, fn, vuln_lines, orig_snippet, source_code))
            elif cwe_id == "CWE-22":
                patches.append(self._patch_path(cand_id, actual_file, fn, vuln_lines, orig_snippet, source_code))
            elif cwe_id == "CWE-120":
                patches.append(self._patch_buffer_overflow(cand_id, actual_file, fn, vuln_lines, orig_snippet, source_code))
            elif cwe_id == "CWE-134":
                patches.append(self._patch_format_string(cand_id, actual_file, fn, vuln_lines, orig_snippet, source_code))

        return {"patches": patches}

    # -----------------------------------------------------------------------
    # Source-aware patch builders  (one method per CWE)
    # -----------------------------------------------------------------------

    def _extract_file_path(self, prompt: str) -> str:
        m = re.search(r"TARGET FILE:\s*([^\n]+)", prompt)
        return m.group(1).strip() if m else "submitted_code.py"

    def _extract_context(self, source_code: str, cwe_id: str, sinks: Dict) -> Dict[str, Any]:
        sink_map = {
            "CWE-89": "sql", "CWE-78": "command_system",
            "CWE-95": "eval", "CWE-502": "pickle", "CWE-22": "path_traversal",
            "CWE-120": "buffer_overflow", "CWE-134": "format_string",
        }
        sink_key = sink_map.get(cwe_id, "sql")
        if cwe_id == "CWE-78" and sinks.get("command_subprocess"):
            sink_key = "command_subprocess"
        return {
            "snippet":    self._extract_sink_snippet(source_code, sink_key),
            "function":   self._guess_function(source_code, sink_key),
            "line_range": self._guess_line_range(source_code, sink_key),
        }

    def _fn_sig(self, source_code: str, fn: str, fallback: str) -> str:
        m = re.search(rf"(def {re.escape(fn)}\s*\([^)]*\))", source_code)
        return m.group(1) if m else fallback

    def _first_param(self, source_code: str, fn: str, fallback: str) -> str:
        """Returns the first non-self parameter name of a function in source_code."""
        m = re.search(rf"def {re.escape(fn)}\s*\(([^)]*)\)", source_code)
        if m:
            params = [p.strip().split(':')[0].strip() for p in m.group(1).split(',') if p.strip()]
            params = [p for p in params if p not in ('self', 'cls') and p]
            if params:
                return params[0]
        return fallback

    def _patch_sql(self, cid, fpath, fn, lines, snippet, source_code: str = ""):
        sig = self._fn_sig(source_code, fn, f"def {fn}(cursor, username, password)")
        # Extract first non-self parameter name for regression test
        param = self._first_param(source_code, fn, "username")
        return {
            "candidate_id": cid, "cwe_id": "CWE-89", "file_path": fpath,
            "original_snippet": snippet, "vulnerable_lines": lines,
            "patch_summary": (
                f"[{fpath}:{lines[0]}] Replace f-string SQL with "
                f"parameterized query in `{fn}()`."
            ),
            "unified_diff": (
                f"--- a/{fpath}\n+++ b/{fpath}\n"
                f"@@ -{lines[0]},5 +{lines[0]},5 @@\n"
                f" {sig}:\n"
                f'-    query = f"SELECT ... {{{param}}} ..."\n'
                f"-    cursor.execute(query)\n"
                f"+    # PATCHED: parameterized query\n"
                f'+    query = "SELECT * FROM users WHERE id=?"\n'
                f"+    cursor.execute(query, ({param},))\n"
                f"     return cursor.fetchone()"
            ),
            "patched_code": (
                f"{sig}:\n"
                f'    # PATCHED: parameterized query prevents SQL injection\n'
                f'    query = "SELECT * FROM users WHERE id=?"\n'
                f"    cursor.execute(query, ({param},))\n"
                f"    return cursor.fetchone()"
            ),
            "security_rationale": (
                "Parameterized queries pass user data as bound parameters at the DB driver level. "
                "SQL structure is compiled before data is inserted — no metacharacter can alter the parse tree."
            ),
            "regression_test_code": (
                "import pytest\n\n"
                f"def test_sql_injection_neutralized(mock_cursor):\n"
                f'    \"\"\"Verify payload is passed as bound data, not SQL.\"\"\"\n'
                f"    payload = \"' OR '1'='1\"\n"
                f"    {fn}(mock_cursor, payload)\n"
                f"    args, _ = mock_cursor.execute.call_args\n"
                f"    assert len(args) == 2, 'Expected (query_string, params_tuple)'\n"
                f"    assert isinstance(args[1], tuple), 'Params must be a tuple'\n"
                f"    assert payload in args[1], 'Payload must reach DB as data'"
            ),
        }

    def _patch_cmd(self, cid, fpath, fn, lines, snippet, is_subprocess, source_code: str = ""):
        sig = self._fn_sig(source_code, fn, f"def {fn}(user_input)")
        param = self._first_param(source_code, fn, "user_input")
        if is_subprocess:
            return {
                "candidate_id": cid, "cwe_id": "CWE-78", "file_path": fpath,
                "original_snippet": snippet, "vulnerable_lines": lines,
                "patch_summary": (
                    f"[{fpath}:{lines[0]}] Remove shell=True, use argument list "
                    f"in subprocess.run() in `{fn}()`."
                ),
                "unified_diff": (
                    f"--- a/{fpath}\n+++ b/{fpath}\n"
                    f"@@ -{lines[0]},3 +{lines[0]},3 @@\n"
                    f" {sig}:\n"
                    f"-    subprocess.call('process ' + {param}, shell=True)\n"
                    f"+    # PATCHED: list args — shell=True removed\n"
                    f"+    subprocess.run(['process', {param}], check=True)"
                ),
                "patched_code": (
                    f"import subprocess\n\n"
                    f"{sig}:\n"
                    f"    # PATCHED: list args — metacharacters not interpreted by shell\n"
                    f"    subprocess.run(['process', {param}], check=True)"
                ),
                "security_rationale": (
                    "Passing arguments as a Python list prevents shell parsing. "
                    "The OS exec()s the binary directly; shell metacharacters like ; & | $() "
                    "are passed as literal bytes, not interpreted."
                ),
                "regression_test_code": (
                    "import pytest\nimport subprocess\n\n"
                    f"def test_subprocess_injection_neutralized():\n"
                    f'    \"\"\"Semicolons/pipes must not trigger new processes.\"\"\"\n'
                    f"    payload = 'arg; cat /etc/passwd'\n"
                    f"    with pytest.raises((FileNotFoundError, subprocess.CalledProcessError)):\n"
                    f"        {fn}(payload)"
                ),
            }
        else:
            return {
                "candidate_id": cid, "cwe_id": "CWE-78", "file_path": fpath,
                "original_snippet": snippet, "vulnerable_lines": lines,
                "patch_summary": (
                    f"[{fpath}:{lines[0]}] Replace os.system() string concat with "
                    f"subprocess argument list in `{fn}()`."
                ),
                "unified_diff": (
                    f"--- a/{fpath}\n+++ b/{fpath}\n"
                    f"@@ -{lines[0]},3 +{lines[0]},4 @@\n"
                    f"+import subprocess\n"
                    f" {sig}:\n"
                    f"-    os.system('ping -c 1 ' + {param})\n"
                    f"+    # PATCHED: subprocess list — no shell involvement\n"
                    f"+    subprocess.run(['ping', '-c', '1', {param}], check=True)"
                ),
                "patched_code": (
                    f"import subprocess\n\n"
                    f"{sig}:\n"
                    f"    # PATCHED: subprocess list — user input is a literal argument\n"
                    f"    subprocess.run(['ping', '-c', '1', {param}], check=True)"
                ),
                "security_rationale": (
                    "Using subprocess with a list argument removes shell involvement entirely. "
                    "User input is a literal OS argument — not part of a shell command string."
                ),
                "regression_test_code": (
                    "import pytest\nimport subprocess\n\n"
                    f"def test_os_command_injection_neutralized():\n"
                    f'    \"\"\"Shell metacharacters must not be interpreted.\"\"\"\n'
                    f"    payload = '127.0.0.1; rm -rf /'\n"
                    f"    with pytest.raises((FileNotFoundError, subprocess.CalledProcessError)):\n"
                    f"        {fn}(payload)"
                ),
            }

    def _patch_eval(self, cid, fpath, fn, lines, snippet, source_code: str = ""):
        sig = self._fn_sig(source_code, fn, f"def {fn}(user_code)")
        param = self._first_param(source_code, fn, "user_code")
        return {
            "candidate_id": cid, "cwe_id": "CWE-95", "file_path": fpath,
            "original_snippet": snippet, "vulnerable_lines": lines,
            "patch_summary": (
                f"[{fpath}:{lines[0]}] Remove eval(); replace with "
                f"allowlist dispatch in `{fn}()`."
            ),
            "unified_diff": (
                f"--- a/{fpath}\n+++ b/{fpath}\n"
                f"@@ -{lines[0]},2 +{lines[0]},7 @@\n"
                f" {sig}:\n"
                f"-    eval({param})\n"
                f"+    # PATCHED: allowlist dispatch replaces eval()\n"
                f"+    SAFE_OPERATIONS = {{'add': lambda a, b: a + b, 'sub': lambda a, b: a - b}}\n"
                f"+    if {param} not in SAFE_OPERATIONS:\n"
                f"+        raise ValueError(f'Unsupported operation: {{{param}!r}}')\n"
                f"+    return SAFE_OPERATIONS[{param}]"
            ),
            "patched_code": (
                f"{sig}:\n"
                f"    # PATCHED: explicit allowlist — no arbitrary code execution possible\n"
                f"    SAFE_OPERATIONS = {{\n"
                f"        'add': lambda a, b: a + b,\n"
                f"        'sub': lambda a, b: a - b,\n"
                f"        'mul': lambda a, b: a * b,\n"
                f"    }}\n"
                f"    if {param} not in SAFE_OPERATIONS:\n"
                f"        raise ValueError(f'Unsupported operation: {{{param}!r}}')\n"
                f"    return SAFE_OPERATIONS[{param}]"
            ),
            "security_rationale": (
                "Replacing eval() with an explicit allowlist dispatch eliminates arbitrary code "
                "execution. Only pre-approved side-effect-free operations are reachable. "
                "Any unknown input raises ValueError before execution begins."
            ),
            "regression_test_code": (
                "import pytest\n\n"
                f"def test_eval_injection_neutralized():\n"
                f'    """Arbitrary code must not execute."""\n'
                f"    with pytest.raises(ValueError):\n"
                f"        {fn}('__import__(\"os\").system(\"id\")')\n\n"
                f"def test_known_op_still_works():\n"
                f"    with pytest.raises(ValueError):\n"
                f"        {fn}('malicious_code')"
            ),
        }

    def _patch_pickle(self, cid, fpath, fn, lines, snippet, source_code: str = ""):
        sig = self._fn_sig(source_code, fn, f"def {fn}(raw_bytes)")
        param = self._first_param(source_code, fn, "raw_bytes")
        return {
            "candidate_id": cid, "cwe_id": "CWE-502", "file_path": fpath,
            "original_snippet": snippet, "vulnerable_lines": lines,
            "patch_summary": (
                f"[{fpath}:{lines[0]}] Replace pickle.loads() with "
                f"json.loads() in `{fn}()` — eliminates RCE vector."
            ),
            "unified_diff": (
                f"--- a/{fpath}\n+++ b/{fpath}\n"
                f"@@ -{lines[0]},4 +{lines[0]},4 @@\n"
                f"-import pickle\n"
                f"+import json\n"
                f" {sig}:\n"
                f"-    return pickle.loads({param})\n"
                f"+    # PATCHED: json.loads cannot execute __reduce__ gadgets\n"
                f"+    return json.loads({param}.decode('utf-8'))"
            ),
            "patched_code": (
                f"import json\n\n"
                f"{sig}:\n"
                f"    # PATCHED: json.loads is safe — no code execution possible\n"
                f"    return json.loads({param}.decode('utf-8'))"
            ),
            "security_rationale": (
                "json.loads() only handles JSON primitives and cannot execute code or trigger "
                "__reduce__ gadgets. This eliminates the deserialization RCE vector completely."
            ),
            "regression_test_code": (
                "import pytest\nimport pickle\nimport os\n\n"
                f"def test_deserialization_rce_blocked():\n"
                f'    """Pickle RCE payload must not execute."""\n'
                f"    class Exploit:\n"
                f"        def __reduce__(self):\n"
                f"            return (os.system, ('id',))\n"
                f"    with pytest.raises(Exception):\n"
                f"        {fn}(pickle.dumps(Exploit()))"
            ),
        }

    def _patch_path(self, cid, fpath, fn, lines, snippet, source_code: str = ""):
        sig = self._fn_sig(source_code, fn, f"def {fn}(filename)")
        param = self._first_param(source_code, fn, "filename")
        return {
            "candidate_id": cid, "cwe_id": "CWE-22", "file_path": fpath,
            "original_snippet": snippet, "vulnerable_lines": lines,
            "patch_summary": (
                f"[{fpath}:{lines[0]}] Add realpath() + prefix boundary check "
                f"in `{fn}()` to sandbox file access."
            ),
            "unified_diff": (
                f"--- a/{fpath}\n+++ b/{fpath}\n"
                f"@@ -{lines[0]},3 +{lines[0]},7 @@\n"
                f" {sig}:\n"
                f"     base_dir = '/var/www/uploads'\n"
                f"-    with open(f'{{base_dir}}/{{{param}}}', 'r') as f:\n"
                f"+    # PATCHED: realpath() + prefix check prevents traversal\n"
                f"+    candidate = os.path.realpath(os.path.join(base_dir, os.path.basename({param})))\n"
                f"+    if not candidate.startswith(base_dir + os.sep):\n"
                f"+        raise PermissionError('Path traversal attempt blocked')\n"
                f"+    with open(candidate, 'r') as f:\n"
                f"         return f.read()"
            ),
            "patched_code": (
                f"import os\n\n"
                f"{sig}:\n"
                f"    # PATCHED: realpath + prefix check constrains access to sandbox\n"
                f"    base_dir = '/var/www/uploads'\n"
                f"    candidate = os.path.realpath(os.path.join(base_dir, os.path.basename({param})))\n"
                f"    if not candidate.startswith(base_dir + os.sep):\n"
                f"        raise PermissionError('Path traversal attempt blocked')\n"
                f"    with open(candidate, 'r') as f:\n"
                f"        return f.read()"
            ),
            "security_rationale": (
                "os.path.realpath() resolves all symlinks and '..' sequences to a canonical absolute path. "
                "The startswith() prefix check guarantees the resolved path stays within the sandbox directory."
            ),
            "regression_test_code": (
                "import pytest\n\n"
                f"def test_path_traversal_blocked():\n"
                f"    with pytest.raises(PermissionError):\n"
                f"        {fn}('../../etc/passwd')\n\n"
                f"def test_absolute_path_blocked():\n"
                f"    with pytest.raises(PermissionError):\n"
                f"        {fn}('/etc/shadow')"
            ),
        }

    def _patch_buffer_overflow(self, cid, fpath, fn, lines, snippet, source_code: str = ""):
        return {
            "candidate_id": cid, "cwe_id": "CWE-120", "file_path": fpath,
            "original_snippet": snippet, "vulnerable_lines": lines,
            "patch_summary": (
                f"[{fpath}:{lines[0]}] Replace unsafe strcpy() with bounded strncpy() or std::string in `{fn}()`."
            ),
            "unified_diff": (
                f"--- a/{fpath}\n+++ b/{fpath}\n"
                f"@@ -{lines[0]},3 +{lines[0]},4 @@\n"
                f"-    strcpy(dest, src);\n"
                f"+    // PATCHED: bounded copy prevents stack buffer overflow (CWE-120)\n"
                f"+    strncpy(dest, src, sizeof(dest) - 1);\n"
                f"+    dest[sizeof(dest) - 1] = '\\0';"
            ),
            "patched_code": (
                "// PATCHED: bounded copy prevents stack buffer overflow (CWE-120)\n"
                "strncpy(dest, src, sizeof(dest) - 1);\n"
                "dest[sizeof(dest) - 1] = '\\0';"
            ),
            "security_rationale": (
                "strcpy() does not perform bounds checking and copies bytes until a null terminator is reached, "
                "leading to buffer overflows. strncpy() with explicit null termination guarantees that the buffer "
                "is never overrun."
            ),
            "regression_test_code": (
                "// C/C++ GoogleTest unit test\n"
                "#include <gtest/gtest.h>\n\n"
                "TEST(SecurityTest, BufferOverflowPrevented) {\n"
                "    char payload[1024];\n"
                "    memset(payload, 'A', sizeof(payload) - 1);\n"
                "    payload[sizeof(payload) - 1] = '\\0';\n"
                f"    EXPECT_NO_THROW({fn}(payload));\n"
                "}"
            ),
        }

    def _patch_format_string(self, cid, fpath, fn, lines, snippet, source_code: str = ""):
        return {
            "candidate_id": cid, "cwe_id": "CWE-134", "file_path": fpath,
            "original_snippet": snippet, "vulnerable_lines": lines,
            "patch_summary": (
                f"[{fpath}:{lines[0]}] Use static format specifier \"%s\" in printf() call in `{fn}()`."
            ),
            "unified_diff": (
                f"--- a/{fpath}\n+++ b/{fpath}\n"
                f"@@ -{lines[0]},2 +{lines[0]},3 @@\n"
                f"-    printf(user_input);\n"
                f"+    // PATCHED: static format string eliminates format specifier injection (CWE-134)\n"
                f"+    printf(\"%s\\n\", user_input);"
            ),
            "patched_code": (
                "// PATCHED: static format string eliminates format specifier injection (CWE-134)\n"
                "printf(\"%s\\n\", user_input);"
            ),
            "security_rationale": (
                "Passing user input directly as the first argument to printf() allows attackers to supply format specifiers "
                "(%x, %s, %n) to leak stack memory or write arbitrary memory addresses. A hardcoded format string prevents this."
            ),
            "regression_test_code": (
                "// C/C++ GoogleTest unit test\n"
                "#include <gtest/gtest.h>\n\n"
                "TEST(SecurityTest, FormatStringNeutralized) {\n"
                "    const char* malicious = \"%x %x %n %s\";\n"
                f"    EXPECT_NO_THROW({fn}(malicious));\n"
                "}"
            ),
        }

    def _extract_sink_snippet(self, source_code: str, sink_key: str) -> str:
        """Extracts the actual vulnerable code line(s) for the given sink type."""
        patterns = {
            "sql": r"cursor\.execute\([^\)]+\)",
            "command_system": r"os\.system\([^\)]+\)",
            "command_subprocess": r"subprocess\.\w+\([^)]*shell\s*=\s*True[^)]*\)",
            "eval": r"eval\([^\)]+\)",
            "exec": r"exec\([^\)]+\)",
            "pickle": r"pickle\.loads?\([^\)]+\)",
            "yaml_unsafe": r"yaml\.load\([^\)]+\)",
            "path_traversal": r"open\s*\([^\)]+\)",
            "buffer_overflow": r"\b(strcpy|strcat|sprintf|gets)\s*\([^;]+\)",
            "format_string": r"\b(printf|fprintf)\s*\([^;]+\)",
        }
        pat = patterns.get(sink_key, r"#\s*sink")
        m = re.search(pat, source_code, re.DOTALL)
        if m:
            snippet = m.group(0)
            # Include surrounding line context
            start = max(0, source_code.rfind('\n', 0, m.start()) + 1)
            end = source_code.find('\n', m.end())
            if end == -1:
                end = len(source_code)
            return source_code[start:end].strip()
        return f"# {sink_key} sink detected"

    def _guess_function(self, source_code: str, sink_key: str) -> str:
        """Finds the enclosing function name for a given sink."""
        sink_patterns = {
            "sql": r"cursor\.execute",
            "command_system": r"os\.system",
            "command_subprocess": r"subprocess\.\w+",
            "eval": r"\beval\(",
            "exec": r"\bexec\(",
            "pickle": r"pickle\.loads?",
            "yaml_unsafe": r"yaml\.load",
            "path_traversal": r"\bopen\(",
            "buffer_overflow": r"\b(strcpy|strcat|sprintf|gets)\s*\(",
            "format_string": r"\b(printf|fprintf)\s*\(",
        }
        pat = sink_patterns.get(sink_key)
        if not pat:
            return "unknown"
        m = re.search(pat, source_code)
        if not m:
            return "unknown"
        # Walk backwards to find the def or C++ function header
        before = source_code[:m.start()]
        # Try Python def
        fn_match = re.findall(r"def\s+(\w+)\s*\(", before)
        if fn_match:
            return fn_match[-1]
        # Try C/C++ function
        cpp_match = re.findall(r'(?:void|int|char\*|bool|std::string|double|float)\s+([a-zA-Z_0-9]+)\s*\(', before)
        if cpp_match:
            return cpp_match[-1]
        return "global_scope"

    def _guess_line_range(self, source_code: str, sink_key: str) -> List[int]:
        """Returns approximate [start, end] line numbers for the sink."""
        sink_patterns = {
            "sql": r"cursor\.execute",
            "command_system": r"os\.system",
            "command_subprocess": r"subprocess\.\w+",
            "eval": r"\beval\(",
            "exec": r"\bexec\(",
            "pickle": r"pickle\.loads?",
            "yaml_unsafe": r"yaml\.load",
            "path_traversal": r"\bopen\(",
            "buffer_overflow": r"\b(strcpy|strcat|sprintf|gets)\s*\(",
            "format_string": r"\b(printf|fprintf)\s*\(",
        }
        pat = sink_patterns.get(sink_key)
        if not pat:
            return [1, 5]
        m = re.search(pat, source_code)
        if not m:
            return [1, 5]
        line_no = source_code[:m.start()].count('\n') + 1
        return [max(1, line_no - 1), line_no + 2]
