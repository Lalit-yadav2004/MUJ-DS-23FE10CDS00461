"""
CodePulse AI - Remediation Engineer / Patch Synthesizer (Stage 3)
=================================================================
Synthesizes surgical unified diffs and automated regression unit tests
for verified security vulnerabilities.
"""

import logging
from typing import Any, Dict, List, Tuple
from prompts.prompt_manager import PromptManager
from src.agents.schemas import AuditedFinding, PatchProposal, StageTelemetry
from src.llm.client import LLMClient
from src.parser.ast_analyzer import CodeStructure

logger = logging.getLogger(__name__)


class PatchSynthesizerAgent:
    """Stage 3: Generates unified diffs and regression tests for confirmed flaws."""

    def __init__(self, llm_client: LLMClient, prompt_manager: PromptManager):
        self.llm_client = llm_client
        self.prompt_manager = prompt_manager

    def synthesize_patches(
        self,
        code_structure: CodeStructure,
        confirmed_findings: List[AuditedFinding],
        force_refresh: bool = False,
    ) -> Tuple[List[PatchProposal], StageTelemetry]:
        actionable_findings = [f for f in confirmed_findings if f.proceed_to_patch]

        if not actionable_findings:
            return [], StageTelemetry(
                stage_name="Patch Synthesizer (Stage 3)",
                model="skipped",
                duration_ms=0,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                cached=False,
            )

        findings_dict = [f.model_dump() for f in actionable_findings]
        prompt_data = self.prompt_manager.compile_patcher_prompt(
            file_path=code_structure.file_path,
            code_content=code_structure.raw_content,
            confirmed_findings=findings_dict,
        )

        response = self.llm_client.generate(
            system_instruction=prompt_data["system_instruction"],
            user_prompt=prompt_data["user_prompt"],
            response_schema=prompt_data["output_schema"],
            force_refresh=force_refresh,
        )

        meta = response.get("metadata", {})
        data = response.get("data", {})

        telemetry = StageTelemetry(
            stage_name="Patch Synthesizer (Stage 3)",
            model=meta.get("model", "gemini-1.5-flash"),
            duration_ms=meta.get("duration_ms", 0),
            prompt_tokens=meta.get("prompt_tokens", 0),
            completion_tokens=meta.get("completion_tokens", 0),
            total_tokens=meta.get("total_tokens", 0),
            cached=meta.get("cached", False),
        )

        raw_patches = data.get("patches", [])
        patches: List[PatchProposal] = []

        for item in raw_patches:
            try:
                patch = PatchProposal(**item)
                patches.append(patch)
            except Exception as e:
                logger.warning(f"Failed to parse patch proposal {item}: {e}")

        return patches, telemetry
