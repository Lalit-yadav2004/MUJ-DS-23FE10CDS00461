"""
CodePulse AI - Interactive Web Dashboard Backend
================================================
FastAPI application providing interactive code security scanning,
AST visualization, multi-agent timeline tracking, and benchmark inspection.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from prompts.prompt_manager import PromptManager
from src.agents.orchestrator import AgentOrchestrator
from src.config import AppSettings, load_settings
from src.parser.ast_analyzer import ASTAnalyzer

app = FastAPI(
    title="CodePulse AI Dashboard",
    description="Enterprise Multi-Agent Code Security Triage & Remediation Engine",
    version="1.0.0",
)

web_dir = Path(__file__).resolve().parent
static_dir = web_dir / "static"
templates_dir = web_dir / "templates"

# Mount static files
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Shared orchestrator
settings = load_settings()
orchestrator = AgentOrchestrator(settings)
prompt_manager = PromptManager()


class AnalyzeRequest(BaseModel):
    code: str
    filename: str = "vulnerable_snippet.py"
    provider: Optional[str] = None
    force_refresh: bool = False


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = templates_dir / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Index template not found")
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "app_name": settings.app_name,
        "version": settings.version,
        "default_provider": settings.llm.default_provider,
        "gemini_api_key_configured": bool(settings.gemini_api_key),
    }


@app.get("/api/presets")
async def get_presets():
    """Returns curated code samples for instant 1-click testing."""
    evals_dir = web_dir.parent / "evals" / "test_corpus"
    presets = []

    samples = [
        ("cwe_89_sqli.py", "CWE-89: SQL Injection", "CRITICAL", "Dangerous string interpolation inside cursor.execute"),
        ("cwe_78_command.py", "CWE-78: OS Command Injection", "CRITICAL", "Unsanitized user host passed to os.system()"),
        ("cwe_22_path.py", "CWE-22: Path Traversal", "HIGH", "Arbitrary file retrieval via unescaped path concatenation"),
        ("cwe_502_pickle.py", "CWE-502: Insecure Deserialization", "CRITICAL", "Arbitrary bytecode execution via pickle.loads()"),
        ("safe_sql_typecasted.py", "Benign Honeypot: Typecasted SQL", "SAFE", "Static scanners flag f-string, but Auditor eliminates as safe int()"),
        ("safe_command_sanitized.py", "Benign Honeypot: shlex.quote", "SAFE", "Safe subprocess call protected with shlex.quote escaping"),
    ]

    for fname, title, severity, desc in samples:
        fpath = evals_dir / fname
        if fpath.exists():
            with open(fpath, "r", encoding="utf-8") as f:
                code_content = f.read()
            presets.append({
                "id": fname,
                "title": title,
                "severity": severity,
                "description": desc,
                "code": code_content,
            })

    return presets


@app.post("/api/analyze")
async def analyze_code(req: AnalyzeRequest):
    """Executes the multi-agent pipeline on user-submitted code."""
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Source code cannot be empty")

    # Handle provider override
    current_settings = load_settings()
    if req.provider:
        current_settings.llm.default_provider = req.provider

    agent_engine = AgentOrchestrator(current_settings)

    try:
        report = agent_engine.analyze_file(
            file_path=req.filename,
            code_content=req.code,
            force_refresh=req.force_refresh,
        )
        return report.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {str(e)}")


@app.get("/api/prompts")
async def get_prompts():
    """Returns the versioned system prompts and schemas for user inspection."""
    prompts_info = {}
    for agent in ["vulnerability_hunter", "security_auditor", "patch_synthesizer"]:
        if agent in prompt_manager._cache:
            p_data = prompt_manager._cache[agent]
            prompts_info[agent] = {
                "agent_name": agent,
                "version": p_data.get("version"),
                "description": p_data.get("description"),
                "system_prompt": p_data.get("system_prompt"),
                "few_shot_count": len(p_data.get("few_shot_examples", [])),
                "output_schema": p_data.get("output_schema"),
            }
    return prompts_info


@app.get("/api/benchmark")
async def get_benchmark_results():
    """Returns saved or fresh benchmark evaluation metrics."""
    bench_file = web_dir.parent / "evals" / "benchmark_results.json"
    if bench_file.exists():
        with open(bench_file, "r", encoding="utf-8") as f:
            return json.load(f)

    # If file doesn't exist, run benchmark once
    from evals.run_evals import run_benchmark
    run_benchmark(force_mock=True)
    with open(bench_file, "r", encoding="utf-8") as f:
        return json.load(f)
