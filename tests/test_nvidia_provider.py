"""
Unit Tests for NvidiaProvider (NVIDIA NIM / API Catalog)
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from src.llm.nvidia_provider import NvidiaProvider


def test_nvidia_provider_raises_without_api_key():
    provider = NvidiaProvider(api_key=None)
    with pytest.raises(ValueError, match="NVIDIA API key is not configured"):
        provider.generate_structured_json(
            system_instruction="System",
            user_prompt="User",
        )


@patch("requests.post")
def test_nvidia_provider_successful_json_generation(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "id": "cmpl-123",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": '```json\n{"candidates": [{"candidate_id": "CAND-001", "cwe_id": "CWE-89"}]}\n```',
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 45,
            "total_tokens": 165,
        },
    }
    mock_post.return_value = mock_resp

    provider = NvidiaProvider(
        api_key="nvapi-test-key",
        model_name="meta/llama-3.3-70b-instruct",
    )

    result = provider.generate_structured_json(
        system_instruction="You are a security hunter.",
        user_prompt="Scan this code",
    )

    assert "data" in result
    assert "candidates" in result["data"]
    assert result["data"]["candidates"][0]["cwe_id"] == "CWE-89"
    assert result["metadata"]["provider"] == "nvidia"
    assert result["metadata"]["model"] == "meta/llama-3.3-70b-instruct"
    assert result["metadata"]["total_tokens"] == 165
    assert mock_post.called


@patch("requests.post")
def test_nvidia_provider_model_override(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": '{"status": "ok"}',
                }
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
    }
    mock_post.return_value = mock_resp

    provider = NvidiaProvider(
        api_key="nvapi-test-key",
        model_name="meta/llama-3.3-70b-instruct",
    )

    result = provider.generate_structured_json(
        system_instruction="Test",
        user_prompt="Test",
        model_override="nvidia/llama-3.1-nemotron-70b-instruct",
    )

    assert result["metadata"]["model"] == "nvidia/llama-3.1-nemotron-70b-instruct"
    payload = mock_post.call_args[1]["json"]
    assert payload["model"] == "nvidia/llama-3.1-nemotron-70b-instruct"
