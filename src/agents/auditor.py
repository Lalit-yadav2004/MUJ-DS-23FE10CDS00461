"""
CodePulse AI - Security Auditor Agent (Stage 2)
===============================================
Adversarial Devil's Advocate agent that stress-tests candidate vulnerabilities
and eliminates false positives by verifying taint flows and defensive controls.
"""

import logging
from typing import Any, Dict, List, Tuple
from prompts.prompt_manager import PromptManager
from src.agents.schemas import AuditedFinding, CandidateVulnerability, StageTelemetry
from src.llm.client import LLMClient
from src.parser.ast_analyzer import CodeStructure

logger = logging.getLogger(__name__)


class AuditorAgent:
    """Stage 2: Adversarial auditor that cross-examines findings to burst false positives."""

    def __init__(self, llm_client: LLMClient, prompt_manager: PromptManager, confidence_threshold: float = 0.65):
        self.llm_client = llm_client
        self.prompt_manager = prompt_manager
        self.confidence_threshold = confidence_threshold

    def audit(
        self,
        code_structure: CodeStructure,
        candidates: List[CandidateVulnerability],
        force_refresh: bool = False,
    ) -> Tuple[List[AuditedFinding], StageTelemetry]:
        if not candidates:
            return [], StageTelemetry(
                stage_name="Security Auditor (Stage 2)",
                model="skipped",
                duration_ms=0,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                cached=False,
            )

        candidates_dict = [c.model_dump() for c in candidates]
        prompt_data = self.prompt_manager.compile_auditor_prompt(
            file_path=code_structure.file_path,
            code_content=code_structure.raw_content,
            candidates=candidates_dict,
            ast_metadata=code_structure.to_metadata_dict(),
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
            stage_name="Security Auditor (Stage 2)",
            model=meta.get("model", "gemini-1.5-flash"),
            duration_ms=meta.get("duration_ms", 0),
            prompt_tokens=meta.get("prompt_tokens", 0),
            completion_tokens=meta.get("completion_tokens", 0),
            total_tokens=meta.get("total_tokens", 0),
            cached=meta.get("cached", False),
        )

        raw_findings = data.get("audited_findings", [])
        findings: List[AuditedFinding] = []

        for item in raw_findings:
            try:
                finding = AuditedFinding(**item)
                # Calibrate proceed_to_patch based on threshold
                if finding.calibrated_confidence < self.confidence_threshold:
                    finding.proceed_to_patch = False
                    if finding.verdict == "CONFIRMED":
                        finding.verdict = "MITIGATED"

                findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse audited finding {item}: {e}")

        return findings, telemetry
