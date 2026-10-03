"""
CodePulse AI - Vulnerability Hunter Agent (Stage 1)
===================================================
Inspects AST-augmented code to discover candidate vulnerabilities.
"""

import logging
from typing import Any, Dict, List, Tuple
from prompts.prompt_manager import PromptManager
from src.agents.schemas import CandidateVulnerability, StageTelemetry
from src.llm.client import LLMClient
from src.parser.ast_analyzer import CodeStructure

logger = logging.getLogger(__name__)


class HunterAgent:
    """Stage 1: Discovers candidate vulnerabilities using Chain-of-Thought reasoning."""

    def __init__(self, llm_client: LLMClient, prompt_manager: PromptManager):
        self.llm_client = llm_client
        self.prompt_manager = prompt_manager

    def hunt(
        self,
        code_structure: CodeStructure,
        active_cwes: List[Dict[str, Any]],
        force_refresh: bool = False,
    ) -> Tuple[List[CandidateVulnerability], StageTelemetry]:
        prompt_data = self.prompt_manager.compile_hunter_prompt(
            file_path=code_structure.file_path,
            code_content=code_structure.raw_content,
            ast_metadata=code_structure.to_metadata_dict(),
            active_cwes=active_cwes,
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
            stage_name="Vulnerability Hunter (Stage 1)",
            model=meta.get("model", "gemini-1.5-flash"),
            duration_ms=meta.get("duration_ms", 0),
            prompt_tokens=meta.get("prompt_tokens", 0),
            completion_tokens=meta.get("completion_tokens", 0),
            total_tokens=meta.get("total_tokens", 0),
            cached=meta.get("cached", False),
        )

        raw_candidates = data.get("candidates", [])
        candidates: List[CandidateVulnerability] = []

        for item in raw_candidates:
            try:
                candidate = CandidateVulnerability(**item)
                candidates.append(candidate)
            except Exception as e:
                logger.warning(f"Failed to validate candidate vulnerability item {item}: {e}")

        return candidates, telemetry
