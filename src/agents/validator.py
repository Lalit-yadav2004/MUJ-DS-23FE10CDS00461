"""
CodePulse AI - Patch Validator Agent (Stage 4)
===============================================
Performs deterministic static validation of synthesized patches before they
are committed. Runs 6 checks: syntax, sink neutralization, safe replacement,
signature integrity, no new sinks, and regression test quality.

For FAIL verdicts, sets regenerate=True so the orchestrator can trigger
a second Patcher pass with the failure feedback embedded.
"""

import ast
import logging
import os
import re
import time
from typing import Any, Dict, List, Literal, Optional, Tuple

from src.agents.schemas import PatchProposal, StageTelemetry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dangerous Sink Patterns (for "no new sinks" scan on patched code)
# ---------------------------------------------------------------------------

_DANGEROUS_SINK_PATTERNS = [
    (r"\beval\s*\(", "eval()"),
    (r"\bexec\s*\(", "exec()"),
    (r"os\.system\s*\(", "os.system()"),
    (r"subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True", "subprocess(shell=True)"),
    (r"pickle\.loads?\s*\(", "pickle.loads()"),
    (r"cursor\.execute\s*\(\s*f['\"]", "f-string SQL"),
    (r"cursor\.execute\s*\(.*?\+", "string-concat SQL"),
]

_SAFE_REPLACEMENT_PATTERNS = {
    "CWE-89": r"cursor\.execute\s*\(\s*(?:['\"][^'\"]*['\"]|\w+)\s*,\s*[(\[]",   # parameterized (literal or query var)
    "CWE-78": r"subprocess\.(run|call|Popen|check_output)\s*\(\s*\[|shlex\.quote", # list form or shlex
    "CWE-95": r"(SAFE_OPERATIONS|allowlist|raise ValueError|ast\.literal_eval)",
    "CWE-502": r"(json\.loads|yaml\.safe_load)",
    "CWE-22": r"(os\.path\.realpath|os\.path\.abspath|os\.path\.basename|startswith)",
}


class PatchCheck:
    """Result container for a single validation check."""
    __slots__ = ("passed", "note")

    def __init__(self, passed: bool, note: str = ""):
        self.passed = passed
        self.note = note


class PatchValidationResult:
    """Full validation result for one patch proposal."""

    def __init__(
        self,
        candidate_id: str,
        cwe_id: str,
        file_path: str,
        verdict: Literal["PASS", "WARN", "FAIL"],
        checks: Dict[str, Any],
        regenerate: bool,
        validation_notes: str,
    ):
        self.candidate_id = candidate_id
        self.cwe_id = cwe_id
        self.file_path = file_path
        self.verdict = verdict
        self.checks = checks
        self.regenerate = regenerate
        self.validation_notes = validation_notes

    def model_dump(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
            "verdict": self.verdict,
            "checks": self.checks,
            "regenerate": self.regenerate,
            "validation_notes": self.validation_notes,
        }


class PatchValidatorAgent:
    """
    Stage 4: Deterministic static validation of synthesized patches.
    Does NOT call the LLM — runs rule-based checks locally for speed and reproducibility.
    """

    def validate_patches(
        self,
        patches: List[PatchProposal],
        original_source: str,
    ) -> Tuple[List[PatchValidationResult], StageTelemetry]:
        start = time.time()

        if not patches:
            return [], StageTelemetry(
                stage_name="Patch Validator (Stage 4)",
                model="static-validator-v1",
                duration_ms=0,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                cached=False,
            )

        results: List[PatchValidationResult] = []
        for patch in patches:
            result = self._validate_single(patch, original_source)
            results.append(result)

        duration_ms = int((time.time() - start) * 1000)
        total_checks = len(patches) * 6  # 6 checks per patch

        telemetry = StageTelemetry(
            stage_name="Patch Validator (Stage 4)",
            model="static-validator-v1",
            duration_ms=duration_ms,
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=total_checks,  # repurpose as check_count for reporting
            cached=False,
        )

        return results, telemetry

    def _validate_single(self, patch: PatchProposal, original_source: str) -> PatchValidationResult:
        """Run all 6 checks against a single patch proposal."""
        notes: List[str] = []
        patched = patch.patched_code or ""
        cwe = patch.cwe_id

        # ------------------------------------------------------------------
        # CHECK 1: Syntax validity (Python & C/C++)
        # ------------------------------------------------------------------
        c1 = self._check_syntax(patched, patch.file_path or "")
        if not c1.passed:
            notes.append(f"CHECK 1 FAILED — Syntax error: {c1.note}")

        # ------------------------------------------------------------------
        # CHECK 2: Original dangerous sink is neutralized
        # ------------------------------------------------------------------
        c2 = self._check_sink_neutralized(patched, cwe, original_source)
        if not c2.passed:
            notes.append(f"CHECK 2 FAILED — Dangerous sink persists: {c2.note}")

        # ------------------------------------------------------------------
        # CHECK 3: Safe replacement exists
        # ------------------------------------------------------------------
        c3 = self._check_safe_replacement(patched, cwe)
        if not c3.passed:
            notes.append(f"CHECK 3 FAILED — No safe replacement found: {c3.note}")

        # ------------------------------------------------------------------
        # CHECK 4: Function signatures not unintentionally changed
        # ------------------------------------------------------------------
        c4 = self._check_signatures_intact(patched, original_source, patch.candidate_id)
        if not c4.passed:
            notes.append(f"CHECK 4 FAILED — Signature change detected: {c4.note}")

        # ------------------------------------------------------------------
        # CHECK 5: No new dangerous sinks in patched code
        # ------------------------------------------------------------------
        c5 = self._check_no_new_sinks(patched, original_source)
        if not c5.passed:
            notes.append(f"CHECK 5 FAILED — New sink introduced: {c5.note}")

        # ------------------------------------------------------------------
        # CHECK 6: Regression test quality (WARN only, not FAIL)
        # ------------------------------------------------------------------
        c6 = self._check_regression_test(patch.regression_test_code or "")

        # ------------------------------------------------------------------
        # Determine overall verdict
        # ------------------------------------------------------------------
        hard_failures = not (c1.passed and c2.passed and c3.passed and c4.passed and c5.passed)

        if hard_failures:
            verdict = "FAIL"
            regenerate = True
        elif c6.passed:
            verdict = "PASS"
            regenerate = False
        else:
            verdict = "WARN"
            regenerate = False
            notes.append(f"CHECK 6 WARN — Regression test issue: {c6.note}")

        validation_notes = (
            " | ".join(notes) if notes
            else "All 6 validation checks passed. Patch is safe to apply."
        )

        checks = {
            "syntax_valid": c1.passed,
            "sink_neutralized": c2.passed,
            "safe_replacement_exists": c3.passed,
            "signatures_intact": c4.passed,
            "no_new_sinks": c5.passed,
            "regression_test_quality": "PASS" if c6.passed else "WARN",
        }

        return PatchValidationResult(
            candidate_id=patch.candidate_id,
            cwe_id=cwe,
            file_path=patch.file_path,
            verdict=verdict,
            checks=checks,
            regenerate=regenerate,
            validation_notes=validation_notes,
        )

    # -----------------------------------------------------------------------
    # Individual Check Implementations
    # -----------------------------------------------------------------------

    def _check_syntax(self, patched_code: str, file_path: str = "") -> PatchCheck:
        if not patched_code.strip():
            return PatchCheck(False, "patched_code is empty")

        ext = os.path.splitext(file_path)[1].lower() if file_path else ""
        is_cpp = ext in [".cpp", ".c", ".cc", ".cxx", ".h", ".hpp"] or (
            "#include" in patched_code or "std::" in patched_code or "int main(" in patched_code
        )
        if is_cpp:
            return self._check_cpp_syntax(patched_code)

        try:
            ast.parse(patched_code)
            return PatchCheck(True)
        except SyntaxError as e:
            return PatchCheck(False, f"line {e.lineno}: {e.msg}")

    def _check_cpp_syntax(self, code: str) -> PatchCheck:
        """Check structural validity (balanced brackets, quotes) for C/C++ snippets."""
        stack = []
        pairs = {')': '(', '}': '{', ']': '['}
        in_string = None
        in_line_comment = False
        in_block_comment = False
        i = 0
        n = len(code)
        while i < n:
            ch = code[i]
            if in_line_comment:
                if ch == '\n':
                    in_line_comment = False
                i += 1
                continue
            if in_block_comment:
                if ch == '*' and i + 1 < n and code[i+1] == '/':
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                if ch == '\\':
                    i += 2
                    continue
                if ch == in_string:
                    in_string = None
                i += 1
                continue
            if ch == '/' and i + 1 < n:
                if code[i+1] == '/':
                    in_line_comment = True
                    i += 2
                    continue
                elif code[i+1] == '*':
                    in_block_comment = True
                    i += 2
                    continue
            if ch in ('"', "'"):
                in_string = ch
                i += 1
                continue
            if ch in ('(', '{', '['):
                stack.append((ch, i))
            elif ch in (')', '}', ']'):
                if not stack or stack[-1][0] != pairs[ch]:
                    return PatchCheck(False, f"Unmatched bracket '{ch}'")
                stack.pop()
            i += 1

        if stack:
            unmatched = stack[-1][0]
            return PatchCheck(False, f"Unclosed bracket '{unmatched}'")
        return PatchCheck(True, "C/C++ syntax structurally valid")

    def _check_sink_neutralized(self, patched: str, cwe: str, original: str) -> PatchCheck:
        """
        Verify the dangerous form of the sink is gone from patched code.
        We check for the CWE-specific dangerous pattern.
        """
        danger_patterns = {
            "CWE-89": [
                r"cursor\.execute\s*\(\s*f['\"]",
                r"cursor\.execute\s*\(.*?\+",
                r'cursor\.execute\s*\(.*?%\s*[^,]',  # %-format without tuple
            ],
            "CWE-78": [
                r"os\.system\s*\(",
                r"subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True",
            ],
            "CWE-95": [r"\beval\s*\(", r"\bexec\s*\("],
            "CWE-502": [r"pickle\.loads?\s*\(", r"yaml\.load\s*\([^)]*Loader\s*=\s*None"],
            "CWE-22": [r"open\s*\(\s*(?:f['\"]|[\w_]+\s*\+)"],
        }

        patterns = danger_patterns.get(cwe, [])
        for pat in patterns:
            if re.search(pat, patched, re.DOTALL):
                return PatchCheck(False, f"Pattern `{pat}` still found in patched code")
        return PatchCheck(True)

    def _check_safe_replacement(self, patched: str, cwe: str) -> PatchCheck:
        pat = _SAFE_REPLACEMENT_PATTERNS.get(cwe)
        if not pat:
            # Unknown CWE — pass with a note
            return PatchCheck(True, "Unknown CWE; safe replacement check skipped")
        if re.search(pat, patched, re.DOTALL | re.IGNORECASE):
            return PatchCheck(True)
        return PatchCheck(False, f"Expected safe pattern for {cwe} not found in patched code")

    def _check_signatures_intact(self, patched: str, original: str, candidate_id: str) -> PatchCheck:
        """
        Extract function def signatures from both and compare names/params.
        Allows body changes; flags name or arity changes as failures.
        """
        def extract_sigs(code: str):
            sigs = {}
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        args = [arg.arg for arg in node.args.args]
                        sigs[node.name] = args
            except SyntaxError:
                pass
            return sigs

        orig_sigs = extract_sigs(original)
        patch_sigs = extract_sigs(patched)

        for fn_name, patch_args in patch_sigs.items():
            if fn_name in orig_sigs:
                orig_args = orig_sigs[fn_name]
                if orig_args != patch_args:
                    return PatchCheck(
                        False,
                        f"Function `{fn_name}` args changed: {orig_args} → {patch_args}"
                    )
        return PatchCheck(True)

    def _check_no_new_sinks(self, patched: str, original: str) -> PatchCheck:
        """Detect sinks present in patched code but NOT in original source."""
        for pat, label in _DANGEROUS_SINK_PATTERNS:
            in_original = bool(re.search(pat, original, re.DOTALL))
            in_patched = bool(re.search(pat, patched, re.DOTALL))
            if in_patched and not in_original:
                return PatchCheck(False, f"New dangerous sink introduced: {label}")
        return PatchCheck(True)

    def _check_regression_test(self, test_code: str) -> PatchCheck:
        if not test_code or not test_code.strip():
            return PatchCheck(False, "regression_test_code is empty")
        has_assert = "assert" in test_code or "pytest.raises" in test_code
        has_def = "def test_" in test_code
        if has_assert and has_def:
            return PatchCheck(True)
        return PatchCheck(
            False,
            "Missing `def test_*` function or no assert/pytest.raises in regression test"
        )
