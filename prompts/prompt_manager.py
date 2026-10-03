"""
CodePulse AI - Enterprise Prompt Manager
========================================
Handles prompt template compilation, versioning, few-shot injection,
and schema formatting across all agent stages.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


class PromptManager:
    """Manages versioned YAML prompts and dynamic template interpolation."""

    def __init__(self, prompts_dir: Optional[Path] = None):
        if prompts_dir is None:
            self.prompts_dir = Path(__file__).resolve().parent
        else:
            self.prompts_dir = Path(prompts_dir)

        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load_all_prompts()

    def _load_all_prompts(self) -> None:
        """Loads and pre-validates all YAML prompt templates in prompts_dir."""
        for yaml_file in self.prompts_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    agent_name = data.get("agent_name", yaml_file.stem)
                    self._cache[agent_name] = data
            except Exception as e:
                print(f"[Warning] Failed to load prompt file {yaml_file}: {e}")

    def get_prompt_metadata(self, agent_name: str) -> Dict[str, Any]:
        """Returns version, description, and target model for an agent."""
        if agent_name not in self._cache:
            raise KeyError(f"Prompt template '{agent_name}' not found. Available: {list(self._cache.keys())}")
        config = self._cache[agent_name]
        return {
            "version": config.get("version", "1.0.0"),
            "agent_name": agent_name,
            "description": config.get("description", ""),
            "target_model": config.get("target_model", "gemini-1.5-flash"),
        }

    def compile_hunter_prompt(
        self,
        file_path: str,
        code_content: str,
        ast_metadata: Dict[str, Any],
        active_cwes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Compiles system instruction, context, and user prompt for Stage 1: Hunter."""
        config = self._cache.get("vulnerability_hunter")
        if not config:
            raise KeyError("Prompt template 'vulnerability_hunter' not found.")

        system_prompt = config["system_prompt"]
        few_shots = config.get("few_shot_examples", [])
        output_schema = config.get("output_schema", {})

        # Context construction
        ast_summary = (
            f"Functions: {list(ast_metadata.get('functions', {}).keys())}\n"
            f"Classes: {list(ast_metadata.get('classes', []))}\n"
            f"Potentially Dangerous Call Sinks: {ast_metadata.get('dangerous_sinks', [])}\n"
            f"Detected Sanitizers/Casting: {ast_metadata.get('sanitizers', [])}"
        )

        user_content = (
            f"TARGET FILE: {file_path}\n"
            f"--- AST METADATA ---\n"
            f"{ast_summary}\n\n"
            f"--- SOURCE CODE ---\n"
            f"```python\n{code_content}\n```\n\n"
            f"TASK: Perform security analysis and return candidate vulnerabilities in deterministic JSON."
        )

        return {
            "system_instruction": system_prompt,
            "few_shot_examples": few_shots,
            "user_prompt": user_content,
            "output_schema": output_schema,
            "version": config.get("version"),
        }

    def compile_auditor_prompt(
        self,
        file_path: str,
        code_content: str,
        candidates: List[Dict[str, Any]],
        ast_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compiles instruction and context for Stage 2: Security Auditor (Devil's Advocate)."""
        config = self._cache.get("security_auditor")
        if not config:
            raise KeyError("Prompt template 'security_auditor' not found.")

        system_prompt = config["system_prompt"]
        few_shots = config.get("few_shot_examples", [])
        output_schema = config.get("output_schema", {})

        candidates_json = json.dumps(candidates, indent=2)

        user_content = (
            f"TARGET FILE: {file_path}\n"
            f"--- AST SANITIZERS & DEFENSES ---\n"
            f"{ast_metadata.get('sanitizers', [])}\n\n"
            f"--- FULL SOURCE CODE ---\n"
            f"```python\n{code_content}\n```\n\n"
            f"--- CANDIDATE VULNERABILITIES TO AUDIT (FROM HUNTER) ---\n"
            f"{candidates_json}\n\n"
            f"TASK: Act as the Devil's Advocate. Ruthlessly challenge each finding. Eliminate false positives. "
            f"Output calibrated confidence scores and audit verdicts strictly in the required JSON schema."
        )

        return {
            "system_instruction": system_prompt,
            "few_shot_examples": few_shots,
            "user_prompt": user_content,
            "output_schema": output_schema,
            "version": config.get("version"),
        }

    def compile_patcher_prompt(
        self,
        file_path: str,
        code_content: str,
        confirmed_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compiles instruction and context for Stage 3: Patch Synthesizer."""
        config = self._cache.get("patch_synthesizer")
        if not config:
            raise KeyError("Prompt template 'patch_synthesizer' not found.")

        system_prompt = config["system_prompt"]
        few_shots = config.get("few_shot_examples", [])
        output_schema = config.get("output_schema", {})

        findings_json = json.dumps(confirmed_findings, indent=2)

        user_content = (
            f"TARGET FILE: {file_path}\n"
            f"--- ORIGINAL SOURCE CODE ---\n"
            f"```python\n{code_content}\n```\n\n"
            f"--- CONFIRMED & AUDITED VULNERABILITIES TO REMEDIATE ---\n"
            f"{findings_json}\n\n"
            f"TASK: Synthesize surgical, minimal-churn unified diffs and pytest regression unit tests. "
            f"Output strictly in the specified JSON schema."
        )

        return {
            "system_instruction": system_prompt,
            "few_shot_examples": few_shots,
            "user_prompt": user_content,
            "output_schema": output_schema,
            "version": config.get("version"),
        }
