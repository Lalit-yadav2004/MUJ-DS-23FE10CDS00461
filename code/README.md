# Code Directory — Batch F NLP Capstone

This directory provides an architectural index of the complete production source code for **CodePulse AI**.

### Component Index
- **`src/agents/`**: Core multi-agent implementations:
  - `hunter.py`: Stage 1 — Vulnerability Hunter Agent
  - `auditor.py`: Stage 2 — Security Auditor (Devil's Advocate Critic)
  - `patcher.py`: Stage 3 — Patch Synthesizer & Remediation Engineer
  - `validator.py`: Stage 4 — Deterministic Patch Validator (6-Check Static Proof-of-Fix)
  - `orchestrator.py`: Multi-Agent Workflow Coordinator & Telemetry Aggregator
  - `schemas.py`: Pydantic V2 data contracts & structured response models
- **`src/parser/`**:
  - `ast_analyzer.py`: Multi-language semantic AST preprocessor (Python, C, C++)
- **`src/llm/`**:
  - `gemini_provider.py`: Google Gemini 3.8 Flash / Pro integration
  - `nvidia_provider.py`: NVIDIA NIM API Catalog integration (Llama 3.3 70B, Nemotron)
  - `mock_provider.py`: High-fidelity offline simulation engine (zero-cost evaluation)
  - `cache.py`: Semantic caching engine
  - `client.py`: Unified LLM client with automatic fallback
- **`prompts/`**: Production YAML prompt definitions & JSON schemas:
  - `vulnerability_hunter.yaml`
  - `security_auditor.yaml`
  - `patch_synthesizer.yaml`
  - `patch_validator.yaml`
  - `prompt_manager.py`
- **`evals/`**: Ground-truth benchmark harness & CWE test corpus
- **`web/`**: Interactive real-time FastAPI & Glassmorphic Web Dashboard
