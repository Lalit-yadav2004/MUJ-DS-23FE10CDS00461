"""
CodePulse AI - Unified LLM Client
=================================
Manages provider routing, fallback policies, semantic caching, and telemetry.
"""

import logging
from typing import Any, Dict, Optional
from src.config import AppSettings
from src.llm.cache import ResponseCache
from src.llm.gemini_provider import GeminiProvider
from src.llm.nvidia_provider import NvidiaProvider
from src.llm.mock_provider import MockProvider

logger = logging.getLogger(__name__)


class LLMClient:
    """Unified client routing requests to Gemini, NVIDIA NIM, or Mock engine with fallback and caching."""

    def __init__(self, settings: AppSettings):
        self.settings = settings
        self.cache = ResponseCache(
            enabled=settings.cache.enabled,
            backend=settings.cache.backend,
            cache_dir=settings.cache.cache_dir,
            ttl=settings.cache.ttl_seconds,
        )

        self.mock_provider = MockProvider(
            simulate_latency=settings.llm.mock.simulate_latency,
            latency_range_ms=settings.llm.mock.latency_range_ms,
        )

        self.gemini_provider: Optional[GeminiProvider] = None
        if settings.gemini_api_key:
            self.gemini_provider = GeminiProvider(
                api_key=settings.gemini_api_key,
                model_name=settings.llm.gemini.model,
                temperature=settings.llm.gemini.temperature,
                max_output_tokens=settings.llm.gemini.max_output_tokens,
                max_retries=settings.llm.gemini.max_retries,
                backoff_factor=settings.llm.gemini.retry_backoff_factor,
            )

        self.nvidia_provider: Optional[NvidiaProvider] = None
        if settings.nvidia_api_key:
            self.nvidia_provider = NvidiaProvider(
                api_key=settings.nvidia_api_key,
                model_name=settings.llm.nvidia.model,
                base_url=settings.llm.nvidia.base_url,
                temperature=settings.llm.nvidia.temperature,
                top_p=settings.llm.nvidia.top_p,
                max_output_tokens=settings.llm.nvidia.max_output_tokens,
                timeout_seconds=settings.llm.nvidia.timeout_seconds,
                max_retries=settings.llm.nvidia.max_retries,
                backoff_factor=settings.llm.nvidia.retry_backoff_factor,
            )

    def generate(
        self,
        system_instruction: str,
        user_prompt: str,
        response_schema: Optional[Dict[str, Any]] = None,
        model_override: Optional[str] = None,
        temperature_override: Optional[float] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Generates structured JSON response, consulting cache and provider routing."""
        provider_name = self.settings.llm.default_provider.lower()
        if provider_name == "nvidia":
            default_model = self.settings.llm.nvidia.model
        elif provider_name == "gemini":
            default_model = self.settings.llm.gemini.model
        else:
            default_model = "mock-engine"

        model_name = model_override or default_model

        # Check cache
        if not force_refresh:
            cached_res = self.cache.get(system_instruction, user_prompt, model_name)
            if cached_res:
                logger.info(f"Cache HIT for model {model_name}")
                # Mark as cached
                cached_res["metadata"]["cached"] = True
                cached_res["metadata"]["duration_ms"] = 1
                return cached_res

        # Route to NVIDIA NIM if selected and configured
        if provider_name == "nvidia" and self.nvidia_provider:
            try:
                res = self.nvidia_provider.generate_structured_json(
                    system_instruction=system_instruction,
                    user_prompt=user_prompt,
                    response_schema=response_schema,
                    model_override=model_override,
                    temperature_override=temperature_override,
                )
                res["metadata"]["cached"] = False
                self.cache.set(system_instruction, user_prompt, model_name, res)
                return res
            except Exception as e:
                logger.warning(
                    f"NVIDIA NIM API invocation failed ({e}). Falling back smoothly to high-fidelity Mock engine..."
                )

        # Route to Gemini if selected and configured
        if provider_name == "gemini" and self.gemini_provider:
            try:
                res = self.gemini_provider.generate_structured_json(
                    system_instruction=system_instruction,
                    user_prompt=user_prompt,
                    response_schema=response_schema,
                    model_override=model_override,
                    temperature_override=temperature_override,
                )
                res["metadata"]["cached"] = False
                self.cache.set(system_instruction, user_prompt, model_name, res)
                return res
            except Exception as e:
                logger.warning(
                    f"Gemini API invocation failed ({e}). Falling back smoothly to high-fidelity Mock engine..."
                )

        # Fallback / Default: Mock engine
        res = self.mock_provider.generate_structured_json(
            system_instruction=system_instruction,
            user_prompt=user_prompt,
            response_schema=response_schema,
            model_override=model_override,
            temperature_override=temperature_override,
        )
        res["metadata"]["cached"] = False
        self.cache.set(system_instruction, user_prompt, model_name, res)
        return res
