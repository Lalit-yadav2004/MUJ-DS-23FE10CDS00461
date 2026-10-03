"""
CodePulse AI - Response & Semantic Cache
========================================
Caches LLM inferences to optimize token costs and guarantee reproducible latency.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional


class ResponseCache:
    """In-memory and file-backed cache for deterministic LLM outputs."""

    def __init__(self, enabled: bool = True, backend: str = "memory", cache_dir: str = ".cache/codepulse", ttl: int = 86400):
        self.enabled = enabled
        self.backend = backend
        self.ttl = ttl
        self.cache_dir = Path(cache_dir)
        self._memory_store: Dict[str, Dict[str, Any]] = {}

        if self.enabled and self.backend == "disk":
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _hash_key(self, system_prompt: str, user_prompt: str, model: str) -> str:
        payload = f"{model}:{system_prompt}:{user_prompt}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def get(self, system_prompt: str, user_prompt: str, model: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        key = self._hash_key(system_prompt, user_prompt, model)
        now = time.time()

        # Check memory
        if key in self._memory_store:
            entry = self._memory_store[key]
            if now - entry["timestamp"] <= self.ttl:
                return entry["data"]
            else:
                del self._memory_store[key]

        # Check disk
        if self.backend == "disk":
            disk_file = self.cache_dir / f"{key}.json"
            if disk_file.exists():
                try:
                    with open(disk_file, "r", encoding="utf-8") as f:
                        entry = json.load(f)
                        if now - entry.get("timestamp", 0) <= self.ttl:
                            # Warm memory
                            self._memory_store[key] = entry
                            return entry.get("data")
                        else:
                            disk_file.unlink(missing_ok=True)
                except Exception:
                    pass

        return None

    def set(self, system_prompt: str, user_prompt: str, model: str, data: Dict[str, Any]) -> None:
        if not self.enabled:
            return

        key = self._hash_key(system_prompt, user_prompt, model)
        entry = {
            "timestamp": time.time(),
            "model": model,
            "data": data,
        }

        self._memory_store[key] = entry

        if self.backend == "disk":
            try:
                disk_file = self.cache_dir / f"{key}.json"
                with open(disk_file, "w", encoding="utf-8") as f:
                    json.dump(entry, f, indent=2)
            except Exception:
                pass

    def clear(self) -> None:
        self._memory_store.clear()
        if self.backend == "disk" and self.cache_dir.exists():
            for f in self.cache_dir.glob("*.json"):
                f.unlink(missing_ok=True)
