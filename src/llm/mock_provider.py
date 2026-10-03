"""
CodePulse AI - High-Fidelity Mock LLM Provider
==============================================
Provides deterministic, rule-informed multi-agent responses for offline testing,
academic evaluation, and CI pipelines without requiring API keys.
"""

import re
import time
from typing import Any, Dict, List, Optional


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

        # Detect which stage is being invoked based on system_instruction
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
        completion_tokens = 250
        total_tokens = prompt_tokens + completion_tokens

        return {
            "data": data,
            "metadata": {
                "provider": "mock",
                "model": "codepulse-mock-engine-v1",
                "duration_ms": duration_ms,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
                "attempts": 1,
            },
        }

    def _mock_hunter(self, prompt: str) -> Dict[str, Any]:
        candidates = []
        cand_idx = 1

        # Check for SQL injection
        if re.search(r"SELECT|cursor\.execute|execute\(.*f[\"']", prompt, re.IGNORECASE):
            candidates.append({
                "candidate_id": f"CAND-00{cand_idx}",
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "severity": "CRITICAL",
                "target_function": "execute_query_or_handler",
                "line_range": [10, 16],
                "vulnerable_code_snippet": "cursor.execute(f\"SELECT * FROM data WHERE id = '{input_val}'\")",
                "source_input": "User-supplied parameter passed without bound parameters",
                "sink_call": "cursor.execute()",
                "taint_path": "input_val -> format string -> cursor.execute()",
                "hypothesis": "Malicious payload could inject SQL operators (e.g. ' OR 1=1) to alter query logic.",
                "initial_confidence": 0.92,
            })
            cand_idx += 1

        # Check for Command Injection
        if re.search(r"os\.system|subprocess\.(Popen|run|call)", prompt):
            candidates.append({
                "candidate_id": f"CAND-00{cand_idx}",
                "cwe_id": "CWE-78",
                "cwe_name": "OS Command Injection",
                "severity": "CRITICAL",
                "target_function": "run_system_task",
                "line_range": [12, 18],
                "vulnerable_code_snippet": "os.system(f'ping -c 1 {host}')",
                "source_input": "host parameter from unvalidated input",
                "sink_call": "os.system()",
                "taint_path": "host -> f-string -> os.system() invocation",
                "hypothesis": "Metacharacters like ';' or '&' allow executing arbitrary shell commands.",
                "initial_confidence": 0.96,
            })
            cand_idx += 1

        # Check for Path Traversal
        if re.search(r"open\(.*f[\"']|open\(.*path|send_file", prompt):
            candidates.append({
                "candidate_id": f"CAND-00{cand_idx}",
                "cwe_id": "CWE-22",
                "cwe_name": "Path Traversal",
                "severity": "HIGH",
                "target_function": "read_user_file",
                "line_range": [8, 12],
                "vulnerable_code_snippet": "with open(f'/var/data/{filename}', 'r') as f:",
                "source_input": "filename input parameter",
                "sink_call": "open()",
                "taint_path": "filename -> directory concatenation -> open()",
                "hypothesis": "Input containing '../../etc/passwd' can escape the intended sandbox directory.",
                "initial_confidence": 0.88,
            })
            cand_idx += 1

        # Check for Insecure Deserialization
        if re.search(r"pickle\.loads|yaml\.load\(.*Loader=None", prompt):
            candidates.append({
                "candidate_id": f"CAND-00{cand_idx}",
                "cwe_id": "CWE-502",
                "cwe_name": "Deserialization of Untrusted Data",
                "severity": "CRITICAL",
                "target_function": "deserialize_payload",
                "line_range": [6, 10],
                "vulnerable_code_snippet": "data = pickle.loads(raw_bytes)",
                "source_input": "raw_bytes payload",
                "sink_call": "pickle.loads()",
                "taint_path": "raw_bytes -> pickle.loads()",
                "hypothesis": "Pickle bytecode can trigger __reduce__ arbitrary code execution upon deserialization.",
                "initial_confidence": 0.98,
            })
            cand_idx += 1

        if not candidates:
            # Benign file or default candidate
            candidates.append({
                "candidate_id": "CAND-001",
                "cwe_id": "CWE-20",
                "cwe_name": "Improper Input Validation",
                "severity": "LOW",
                "target_function": "process_request",
                "line_range": [5, 8],
                "vulnerable_code_snippet": "# Potential generic input processing",
                "source_input": "Generic request body",
                "sink_call": "Standard handler",
                "taint_path": "request -> handler",
                "hypothesis": "Input could benefit from stricter schema validation.",
                "initial_confidence": 0.40,
            })

        return {"candidates": candidates}

    def _mock_auditor(self, prompt: str) -> Dict[str, Any]:
        audited = []
        # Check if the code has sanitization indicators
        has_int_cast = "int(" in prompt or "clean_id" in prompt or "isinstance(" in prompt
        has_shlex = "shlex.quote" in prompt or "basename" in prompt or "abspath" in prompt or "parametrized" in prompt

        # Parse candidate IDs from prompt
        cands = re.findall(r'"candidate_id":\s*"(CAND-\d+)"', prompt)
        if not cands:
            cands = ["CAND-001"]

        for cand_id in cands:
            if has_int_cast or has_shlex:
                # Devil's Advocate successfully identified defense mechanism!
                audited.append({
                    "candidate_id": cand_id,
                    "cwe_id": "CWE-89" if "CWE-89" in prompt else "CWE-78",
                    "verdict": "REJECTED_FALSE_POSITIVE",
                    "calibrated_confidence": 0.12,
                    "defense_mechanisms_found": [
                        "Explicit type coercion or boundary validation detected before dangerous sink",
                        "Attacker payload cannot break lexical boundary due to pre-execution transformation",
                    ],
                    "attack_feasibility": "UNEXPLOITABLE",
                    "audit_rationale": "Auditor verification confirmed that defensive controls (e.g. type casting or path resolution) neutralize the taint path. Eliminating candidate as false positive.",
                    "proceed_to_patch": False,
                })
            else:
                # Real confirmed vulnerability
                audited.append({
                    "candidate_id": cand_id,
                    "cwe_id": "CWE-89" if "CWE-89" in prompt else ("CWE-78" if "CWE-78" in prompt else "CWE-22"),
                    "verdict": "CONFIRMED",
                    "calibrated_confidence": 0.94,
                    "defense_mechanisms_found": [],
                    "attack_feasibility": "HIGH",
                    "audit_rationale": "Adversarial analysis verified that untrusted input propagates directly into the execution sink without sanitization or parameter binding.",
                    "proceed_to_patch": True,
                })

        return {"audited_findings": audited}

    def _mock_patcher(self, prompt: str) -> Dict[str, Any]:
        patches = []
        cands = re.findall(r'"candidate_id":\s*"(CAND-\d+)"', prompt)
        if not cands:
            cands = ["CAND-001"]

        for cand_id in cands:
            if "CWE-78" in prompt or "system" in prompt:
                patches.append({
                    "candidate_id": cand_id,
                    "cwe_id": "CWE-78",
                    "file_path": "service.py",
                    "patch_summary": "Replaced dangerous shell string formatting with subprocess list argument array.",
                    "unified_diff": "--- a/service.py\n+++ b/service.py\n@@ -10,3 +10,4 @@\n-    os.system(f'ping -c 1 {host}')\n+    import subprocess\n+    subprocess.run(['ping', '-c', '1', host], check=True)",
                    "patched_code": "import subprocess\ndef run_task(host):\n    subprocess.run(['ping', '-c', '1', host], check=True)",
                    "security_rationale": "Passing arguments as a list to subprocess bypasses shell interpreter parsing, eliminating command injection.",
                    "regression_test_code": "def test_command_injection_neutralized():\n    bad_host = '127.0.0.1; cat /etc/passwd'\n    # Verified that semicolon is treated as a literal argument rather than shell separator\n    assert True",
                })
            elif "CWE-22" in prompt or "open" in prompt:
                patches.append({
                    "candidate_id": cand_id,
                    "cwe_id": "CWE-22",
                    "file_path": "file_service.py",
                    "patch_summary": "Enforced directory boundary check using os.path.realpath and commonpath.",
                    "unified_diff": "--- a/file_service.py\n+++ b/file_service.py\n@@ -8,3 +8,6 @@\n-    with open(f'/var/data/{filename}', 'r') as f:\n+    safe_path = os.path.realpath(os.path.join('/var/data', os.path.basename(filename)))\n+    if not safe_path.startswith('/var/data/'):\n+        raise ValueError('Unauthorized directory traversal detected')\n+    with open(safe_path, 'r') as f:",
                    "patched_code": "safe_path = os.path.realpath(os.path.join('/var/data', os.path.basename(filename)))\nif not safe_path.startswith('/var/data/'): raise ValueError('Invalid path')",
                    "security_rationale": "basename and realpath bound the resolved target to the designated directory.",
                    "regression_test_code": "def test_path_traversal_blocked():\n    import pytest\n    with pytest.raises(ValueError):\n        read_user_file('../../etc/passwd')",
                })
            else:
                # Default SQL injection patch
                patches.append({
                    "candidate_id": cand_id,
                    "cwe_id": "CWE-89",
                    "file_path": "db_ops.py",
                    "patch_summary": "Replaced formatted f-string query with parameterized SQL query placeholder.",
                    "unified_diff": "--- a/db_ops.py\n+++ b/db_ops.py\n@@ -12,4 +12,4 @@\n-    query = f\"SELECT * FROM data WHERE id = '{input_val}'\"\n-    cursor.execute(query)\n+    query = \"SELECT * FROM data WHERE id = ?\"\n+    cursor.execute(query, (input_val,))",
                    "patched_code": "query = \"SELECT * FROM data WHERE id = ?\"\ncursor.execute(query, (input_val,))",
                    "security_rationale": "Parameterized query binds user input as literal scalar value, preventing query structure tampering.",
                    "regression_test_code": "def test_sql_injection_defense():\n    malicious = \"' OR '1'='1\"\n    # Payload treated strictly as literal string\n    assert True",
                })

        return {"patches": patches}
