"""
CodePulse AI - Multi-Agent Pipeline Orchestrator
================================================
Coordinates Stage 1 (Hunter), Stage 2 (Auditor), and Stage 3 (Patch Synthesizer)
into an end-to-end deterministic code security workflow with telemetry.
"""

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from prompts.prompt_manager import PromptManager
from src.agents.auditor import AuditorAgent
from src.agents.hunter import HunterAgent
from src.agents.patcher import PatchSynthesizerAgent
from src.agents.schemas import StageTelemetry, TriageReport
from src.config import AppSettings, load_settings
from src.llm.client import LLMClient
from src.parser.ast_analyzer import ASTAnalyzer

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """Enterprise multi-agent triage coordinator."""

    def __init__(self, settings: Optional[AppSettings] = None):
        self.settings = settings or load_settings()
        self.prompt_manager = PromptManager()
        self.llm_client = LLMClient(self.settings)

        self.hunter = HunterAgent(self.llm_client, self.prompt_manager)
        self.auditor = AuditorAgent(
            self.llm_client,
            self.prompt_manager,
            confidence_threshold=self.settings.agents.auditor.confidence_threshold,
        )
        self.patcher = PatchSynthesizerAgent(self.llm_client, self.prompt_manager)

    def analyze_file(
        self,
        file_path: str,
        code_content: Optional[str] = None,
        force_refresh: bool = False,
    ) -> TriageReport:
        """Executes full 3-tier multi-agent pipeline on a target source file."""
        pipeline_start = time.time()

        # Step 0: AST & Semantic Preprocessing
        code_structure = ASTAnalyzer.analyze_file(file_path, content=code_content)

        telemetry_stages: List[StageTelemetry] = []

        # Step 1: Hunter (Candidate Discovery)
        candidates, hunter_telemetry = self.hunter.hunt(
            code_structure=code_structure,
            active_cwes=self.settings.active_cwes,
            force_refresh=force_refresh,
        )
        hunter_telemetry.estimated_cost_usd = self._compute_cost(hunter_telemetry)
        telemetry_stages.append(hunter_telemetry)

        # Step 2: Security Auditor (Adversarial False-Positive Buster)
        findings, auditor_telemetry = self.auditor.audit(
            code_structure=code_structure,
            candidates=candidates,
            force_refresh=force_refresh,
        )
        auditor_telemetry.estimated_cost_usd = self._compute_cost(auditor_telemetry)
        telemetry_stages.append(auditor_telemetry)

        # Step 3: Patch Synthesizer (Unified Diff & Regression Tests)
        patches, patcher_telemetry = self.patcher.synthesize_patches(
            code_structure=code_structure,
            confirmed_findings=findings,
            force_refresh=force_refresh,
        )
        patcher_telemetry.estimated_cost_usd = self._compute_cost(patcher_telemetry)
        telemetry_stages.append(patcher_telemetry)

        # Compute summary statistics
        total_candidates = len(candidates)
        confirmed_count = sum(1 for f in findings if f.verdict == "CONFIRMED")
        false_positives = sum(1 for f in findings if f.verdict == "REJECTED_FALSE_POSITIVE")
        mitigated_count = sum(1 for f in findings if f.verdict == "MITIGATED")

        fp_reduction_rate = (
            (false_positives / total_candidates * 100.0) if total_candidates > 0 else 0.0
        )

        overall_status = "CLEAN"
        if confirmed_count > 0:
            overall_status = "VULNERABILITIES_CONFIRMED"
        elif false_positives > 0:
            overall_status = "FALSE_POSITIVES_BURNT"

        total_prompt_tokens = sum(t.prompt_tokens for t in telemetry_stages)
        total_completion_tokens = sum(t.completion_tokens for t in telemetry_stages)
        total_tokens = sum(t.total_tokens for t in telemetry_stages)
        total_cost_usd = sum(t.estimated_cost_usd for t in telemetry_stages)
        total_duration_ms = int((time.time() - pipeline_start) * 1000)

        summary_stats = {
            "total_candidates_flagged": total_candidates,
            "confirmed_vulnerabilities": confirmed_count,
            "false_positives_eliminated": false_positives,
            "mitigated_flaws": mitigated_count,
            "false_positive_reduction_pct": round(fp_reduction_rate, 1),
            "patches_synthesized": len(patches),
            "total_tokens_consumed": total_tokens,
            "total_cost_usd": round(total_cost_usd, 6),
            "pipeline_latency_ms": total_duration_ms,
        }

        return TriageReport(
            file_path=file_path,
            language=code_structure.language,
            total_lines=code_structure.total_lines,
            ast_metadata=code_structure.to_metadata_dict(),
            hunter_candidates=candidates,
            audited_findings=findings,
            patches=patches,
            telemetry=telemetry_stages,
            overall_status=overall_status,
            summary_statistics=summary_stats,
        )

    def _compute_cost(self, telemetry: StageTelemetry) -> float:
        """Estimates cost based on model and token counts."""
        model_name = telemetry.model.lower()
        cost_rates = self.settings.telemetry.cost_rates if hasattr(self.settings, "telemetry") else {}

        # Default Gemini 1.5 Flash rates ($0.075 / 1M input, $0.30 / 1M output)
        input_rate = 0.075 / 1_000_000
        output_rate = 0.30 / 1_000_000

        if "pro" in model_name:
            input_rate = 1.25 / 1_000_000
            output_rate = 5.00 / 1_000_000

        return (telemetry.prompt_tokens * input_rate) + (telemetry.completion_tokens * output_rate)
