"""
CodePulse AI - Google Gemini API Provider
=========================================
Implements direct Google Gemini API integration with structured JSON responses,
usage metadata tracking, and exponential backoff retry.
"""

import json
import logging
import random
import time
import warnings
from typing import Any, Dict, Optional

# Suppress library deprecation notices for clean terminal & web output
warnings.filterwarnings("ignore")

import google.generativeai as genai
from google.api_core import exceptions as google_exceptions

logger = logging.getLogger(__name__)


class GeminiProvider:
    """Wrapper for Google Gemini 1.5 Flash / Pro with structured output guarantees."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "gemini-1.5-flash",
        temperature: float = 0.1,
        max_output_tokens: int = 3072,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
    ):
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        if self.api_key:
            genai.configure(api_key=self.api_key)

    def generate_structured_json(
        self,
        system_instruction: str,
        user_prompt: str,
        response_schema: Optional[Dict[str, Any]] = None,
        model_override: Optional[str] = None,
        temperature_override: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Calls Gemini API with strict JSON mode and tracks token metrics."""
        if not self.api_key:
            raise ValueError(
                "Gemini API key is not configured. Set GEMINI_API_KEY environment variable or pass api_key."
            )

        active_model_name = model_override or self.model_name
        active_temp = temperature_override if temperature_override is not None else self.temperature

        # Initialize model with system instruction
        model = genai.GenerativeModel(
            model_name=active_model_name,
            system_instruction=system_instruction,
            generation_config=genai.GenerationConfig(
                temperature=active_temp,
                max_output_tokens=self.max_output_tokens,
                response_mime_type="application/json",
            ),
        )

        last_error = None
        start_time = time.time()

        for attempt in range(1, self.max_retries + 1):
            try:
                response = model.generate_content(user_prompt)
                duration_ms = int((time.time() - start_time) * 1000)

                raw_text = response.text or "{}"
                # Clean up if markdown code fence is accidentally wrapped
                clean_text = raw_text.strip()
                if clean_text.startswith("```json"):
                    clean_text = clean_text[7:]
                if clean_text.startswith("```"):
                    clean_text = clean_text[3:]
                if clean_text.endswith("```"):
                    clean_text = clean_text[:-3]
                clean_text = clean_text.strip()

                parsed_json = json.loads(clean_text)

                # Extract token usage metadata
                usage = getattr(response, "usage_metadata", None)
                prompt_tokens = getattr(usage, "prompt_token_count", 0) if usage else len(user_prompt.split()) * 2
                completion_tokens = getattr(usage, "candidates_token_count", 0) if usage else len(clean_text.split()) * 2
                total_tokens = getattr(usage, "total_token_count", 0) if usage else (prompt_tokens + completion_tokens)

                return {
                    "data": parsed_json,
                    "metadata": {
                        "provider": "gemini",
                        "model": active_model_name,
                        "duration_ms": duration_ms,
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": total_tokens,
                        "attempts": attempt,
                    },
                }

            except (google_exceptions.ResourceExhausted, google_exceptions.ServiceUnavailable) as e:
                last_error = e
                wait_time = (self.backoff_factor ** attempt) + random.uniform(0.1, 0.5)
                logger.warning(f"Rate limited by Gemini API. Retrying in {wait_time:.2f}s (Attempt {attempt}/{self.max_retries})...")
                time.sleep(wait_time)
            except json.JSONDecodeError as jde:
                logger.error(f"Malformed JSON from Gemini: {jde}. Raw text was: {response.text}")
                last_error = jde
                break
            except Exception as e:
                logger.error(f"Gemini API invocation failed: {e}")
                last_error = e
                time.sleep(1.0)

        raise RuntimeError(f"Gemini Provider failed after {self.max_retries} attempts: {last_error}")
