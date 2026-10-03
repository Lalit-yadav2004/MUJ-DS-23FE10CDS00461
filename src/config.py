"""
CodePulse AI - Central Configuration Loader
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load .env if present
load_dotenv()


class GeminiConfig(BaseModel):
    model: str = "models/gemini-3.8-flash"
    fallback_model: str = "models/gemini-3.1-pro-preview"
    temperature: float = 0.1
    max_output_tokens: int = 3072
    timeout_seconds: int = 45
    max_retries: int = 3
    retry_backoff_factor: float = 2.0


class MockConfig(BaseModel):
    simulate_latency: bool = True
    latency_range_ms: List[int] = [300, 700]


class LLMConfig(BaseModel):
    default_provider: str = "gemini"
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    mock: MockConfig = Field(default_factory=MockConfig)


class HunterConfig(BaseModel):
    temperature: float = 0.1
    top_p: float = 0.95
    max_candidates_per_file: int = 5
    enable_cot_reasoning: bool = True


class AuditorConfig(BaseModel):
    temperature: float = 0.05
    confidence_threshold: float = 0.65
    require_exploit_path: bool = True
    cross_check_sanitizers: bool = True


class PatcherConfig(BaseModel):
    temperature: float = 0.1
    generate_diff: bool = True
    generate_regression_tests: bool = True
    enforce_backward_compatibility: bool = True


class AgentsConfig(BaseModel):
    hunter: HunterConfig = Field(default_factory=HunterConfig)
    auditor: AuditorConfig = Field(default_factory=AuditorConfig)
    patcher: PatcherConfig = Field(default_factory=PatcherConfig)


class ParserConfig(BaseModel):
    max_file_size_kb: int = 512
    supported_extensions: List[str] = [".py", ".js", ".ts", ".go"]
    extract_call_graph: bool = True
    extract_sanitizer_nodes: bool = True


class CacheConfig(BaseModel):
    enabled: bool = True
    backend: str = "memory"
    cache_dir: str = ".cache/codepulse"
    ttl_seconds: int = 86400


class AppSettings(BaseModel):
    app_name: str = "CodePulse AI"
    version: str = "1.0.0"
    environment: str = "production"
    debug: bool = False
    llm: LLMConfig = Field(default_factory=LLMConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    parser: ParserConfig = Field(default_factory=ParserConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    active_cwes: List[Dict[str, Any]] = Field(default_factory=list)

    # API Keys & Secrets from env
    gemini_api_key: Optional[str] = None


def load_settings(config_path: Optional[str] = None) -> AppSettings:
    """Loads settings from config.yaml and merges with environment variables."""
    root_dir = Path(__file__).resolve().parent.parent
    if config_path is None:
        path = root_dir / "config.yaml"
    else:
        path = Path(config_path)

    raw_yaml: Dict[str, Any] = {}
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            raw_yaml = yaml.safe_load(f) or {}

    app_meta = raw_yaml.get("app", {})
    llm_data = raw_yaml.get("llm", {})
    agents_data = raw_yaml.get("agents", {})
    parser_data = raw_yaml.get("parser", {})
    cache_data = raw_yaml.get("cache", {})
    ruleset_data = raw_yaml.get("ruleset", {})

    settings = AppSettings(
        app_name=app_meta.get("name", "CodePulse AI"),
        version=app_meta.get("version", "1.0.0"),
        environment=app_meta.get("environment", "production"),
        debug=app_meta.get("debug", False),
        llm=LLMConfig(**llm_data) if llm_data else LLMConfig(),
        agents=AgentsConfig(**agents_data) if agents_data else AgentsConfig(),
        parser=ParserConfig(**parser_data) if parser_data else ParserConfig(),
        cache=CacheConfig(**cache_data) if cache_data else CacheConfig(),
        active_cwes=ruleset_data.get("active_cwes", []),
        gemini_api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"),
    )

    # Allow CLI / env provider override
    env_provider = os.getenv("CODEPULSE_PROVIDER")
    if env_provider:
        settings.llm.default_provider = env_provider.lower()

    return settings
