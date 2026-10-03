"""
CodePulse AI - Domain Models & Pydantic Schemas
===============================================
Defines deterministic, strongly-typed contracts for all multi-agent stages.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class CandidateVulnerability(BaseModel):
    """Candidate vulnerability identified by the Hunter agent (Stage 1)."""
    candidate_id: str = Field(description="Unique candidate identifier, e.g. CAND-001")
    cwe_id: str = Field(description="Common Weakness Enumeration ID, e.g. CWE-89")
    cwe_name: str = Field(description="Standard vulnerability category name")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "MEDIUM"
    target_function: str = Field(description="Function or method where the vulnerability resides")
    line_range: List[int] = Field(default_factory=lambda: [1, 1], description="[start_line, end_line]")
    vulnerable_code_snippet: str = Field(description="Source code snippet showing the vulnerable logic")
    source_input: str = Field(description="Originating untrusted input source")
    sink_call: str = Field(description="Dangerous execution sink")
    taint_path: str = Field(description="Step-by-step propagation from source to sink")
    hypothesis: str = Field(description="Theoretical exploit scenario")
    initial_confidence: float = Field(ge=0.0, le=1.0, description="Hunter initial confidence score")


class AuditedFinding(BaseModel):
    """Adversarial stress-test result from the Security Auditor agent (Stage 2)."""
    candidate_id: str = Field(description="Reference to Hunter candidate ID")
    cwe_id: str = Field(description="CWE ID under audit")
    verdict: Literal["CONFIRMED", "REJECTED_FALSE_POSITIVE", "MITIGATED"]
    calibrated_confidence: float = Field(ge=0.0, le=1.0, description="Calibrated confidence after adversarial review")
    defense_mechanisms_found: List[str] = Field(default_factory=list, description="Sanitizers, castings, or controls detected")
    attack_feasibility: Literal["HIGH", "MEDIUM", "LOW", "UNEXPLOITABLE"] = "LOW"
    audit_rationale: str = Field(description="Devil's advocate reasoning explaining why this is real or false positive")
    proceed_to_patch: bool = Field(description="True if verified and requires remediation")


class PatchProposal(BaseModel):
    """Surgical unified diff and regression test from the Patch Synthesizer (Stage 3)."""
    candidate_id: str = Field(description="Reference to confirmed candidate ID")
    cwe_id: str = Field(description="CWE ID remediated")
    file_path: str = Field(description="Target file path")
    patch_summary: str = Field(description="High-level description of the security fix")
    unified_diff: str = Field(description="Standard git apply compatible diff")
    patched_code: str = Field(description="Clean, secure rewritten code block")
    security_rationale: str = Field(description="Why this specific fix prevents future bypasses")
    regression_test_code: str = Field(description="Pytest unit test verifying the fix and checking edge cases")


class StageTelemetry(BaseModel):
    """Execution telemetry for a single agent stage."""
    stage_name: str
    model: str
    duration_ms: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    estimated_cost_usd: float = 0.0
    cached: bool = False


class TriageReport(BaseModel):
    """Comprehensive end-to-end report for a scanned file."""
    file_path: str
    language: str
    total_lines: int
    ast_metadata: Dict[str, Any]
    hunter_candidates: List[CandidateVulnerability] = Field(default_factory=list)
    audited_findings: List[AuditedFinding] = Field(default_factory=list)
    patches: List[PatchProposal] = Field(default_factory=list)
    telemetry: List[StageTelemetry] = Field(default_factory=list)
    overall_status: Literal["CLEAN", "VULNERABILITIES_CONFIRMED", "FALSE_POSITIVES_BURNT"] = "CLEAN"
    summary_statistics: Dict[str, Any] = Field(default_factory=dict)
