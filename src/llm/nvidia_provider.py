"""
CodePulse AI - NVIDIA NIM / API Catalog Provider
================================================
Implements integration with NVIDIA NIM (https://build.nvidia.com/models)
providing enterprise-grade LLM inference (e.g., Llama 3.3 70B Instruct,
NVIDIA Nemotron 70B, DeepSeek R1, Qwen 2.5 Coder) with structured JSON
enforcement, telemetry tracking, and exponential backoff retry.
"""

import json
import logging
import random
import re
import time
from typing import Any, Dict, Optional
import requests

logger = logging.getLogger(__name__)

# Default model on NVIDIA NIM (build.nvidia.com)
DEFAULT_NVIDIA_MODEL = "meta/llama-3.3-70b-instruct"
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1/chat/completions"


class NvidiaProvider:
    """
    Client for NVIDIA NIM (API Catalog) OpenAI-compatible chat completions endpoint.
    Supports meta/llama-3.3-70b-instruct, nvidia/llama-3.1-nemotron-70b-instruct,
    deepseek-ai/deepseek-r1, qwen/qwen2.5-coder-32b-instruct, etc.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = DEFAULT_NVIDIA_MODEL,
        base_url: str = NVIDIA_BASE_URL,
        temperature: float = 0.1,
        top_p: float = 0.95,
        max_output_tokens: int = 3072,
        timeout_seconds: int = 60,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
    ):
        self.api_key = api_key
        self.model_name = model_name
        self.base_url = base_url
        self.temperature = temperature
        self.top_p = top_p
        self.max_output_tokens = max_output_tokens
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    def generate_structured_json(
        self,
        system_instruction: str,
        user_prompt: str,
        response_schema: Optional[Dict[str, Any]] = None,
        model_override: Optional[str] = None,
        temperature_override: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Invokes NVIDIA NIM with system instructions and user prompt,
        ensuring clean JSON parsing and token telemetry tracking.
        """
        if not self.api_key:
            raise ValueError(
                "NVIDIA API key is not configured. Set NVIDIA_API_KEY environment variable or pass api_key."
            )

        active_model = model_override or self.model_name
        active_temp = temperature_override if temperature_override is not None else self.temperature

        # Inject JSON instruction if not already present
        system_msg = system_instruction
        if "JSON" not in system_msg.upper():
            system_msg += "\n\nCRITICAL: Respond ONLY with valid, raw RFC-8259 JSON. Do not include markdown explanation."

        payload = {
            "model": active_model,
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": active_temp,
            "top_p": self.top_p,
            "max_tokens": self.max_output_tokens,
            "response_format": {"type": "json_object"},
        }

        headers = {
            "Authorization": f"Bearer {self.api_key.strip()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CodePulse-AI-SecurityScanner/1.0",
        }

        last_error = None
        start_time = time.time()

        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.post(
                    self.base_url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
                duration_ms = int((time.time() - start_time) * 1000)

                # Check for rate limit or server busy
                if response.status_code == 429:
                    wait_time = (self.backoff_factor ** attempt) + random.uniform(0.2, 0.8)
                    logger.warning(
                        f"NVIDIA API rate limited (429). Retrying in {wait_time:.2f}s (Attempt {attempt}/{self.max_retries})..."
                    )
                    time.sleep(wait_time)
                    continue

                if response.status_code >= 500:
                    wait_time = (self.backoff_factor ** attempt) + random.uniform(0.2, 0.8)
                    logger.warning(
                        f"NVIDIA API server error ({response.status_code}). Retrying in {wait_time:.2f}s..."
                    )
                    time.sleep(wait_time)
                    continue

                if response.status_code != 200:
                    err_msg = f"NVIDIA API returned HTTP {response.status_code}: {response.text}"
                    logger.error(err_msg)
                    raise RuntimeError(err_msg)

                res_json = response.json()
                choices = res_json.get("choices", [])
                if not choices:
                    raise ValueError("NVIDIA API response contained empty choices array.")

                raw_content = choices[0].get("message", {}).get("content", "").strip()

                # Clean markdown code fences if wrapped
                clean_text = raw_content
                if clean_text.startswith("```json"):
                    clean_text = clean_text[7:]
                if clean_text.startswith("```"):
                    clean_text = clean_text[3:]
                if clean_text.endswith("```"):
                    clean_text = clean_text[:-3]
                clean_text = clean_text.strip()

                # Extract first JSON object if surrounded by preamble
                if not clean_text.startswith("{") and "{" in clean_text:
                    m = re.search(r"(\{.*\})", clean_text, re.DOTALL)
                    if m:
                        clean_text = m.group(1)

                parsed_data = json.loads(clean_text)

                # Extract token usage
                usage = res_json.get("usage", {})
                prompt_tokens = usage.get("prompt_tokens") or len(user_prompt.split()) * 2
                completion_tokens = usage.get("completion_tokens") or len(clean_text.split()) * 2
                total_tokens = usage.get("total_tokens") or (prompt_tokens + completion_tokens)

                return {
                    "data": parsed_data,
                    "metadata": {
                        "provider": "nvidia",
                        "model": active_model,
                        "duration_ms": duration_ms,
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": total_tokens,
                        "attempts": attempt,
                    },
                }

            except json.JSONDecodeError as jde:
                logger.error(f"Malformed JSON from NVIDIA NIM: {jde}. Raw text was: {raw_content[:200]}")
                last_error = jde
                # Retry once if output was truncated
                time.sleep(0.5)
            except requests.exceptions.Timeout as te:
                logger.warning(f"NVIDIA API timeout on attempt {attempt}/{self.max_retries}")
                last_error = te
                time.sleep(1.0)
            except requests.exceptions.RequestException as re_err:
                logger.error(f"NVIDIA API network error: {re_err}")
                last_error = re_err
                time.sleep(1.0)
            except Exception as e:
                logger.error(f"NVIDIA API invocation error: {e}")
                last_error = e
                time.sleep(1.0)

        raise RuntimeError(f"NVIDIA NIM Provider failed after {self.max_retries} attempts: {last_error}")
