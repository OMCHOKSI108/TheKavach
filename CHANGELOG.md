# Changelog

## v0.2.0 - Hybrid Detection Upgrade (2026-06-07)

### Added
- **Hybrid ML + Rule-Based Detector** (`models/hybrid_detector.py`)
  - 8 rule categories with 60+ regex patterns
  - SQL injection, XSS, command injection, path traversal, scanning, brute force, malware, suspicious network
  - Configurable override thresholds
  - Transparent explanations for every decision
- **Configurable thresholds** via `.env` / `backend/core/config.py`
  - `MODEL_HIGH_CONFIDENCE_THRESHOLD`, `MALICIOUS_OVERRIDE_THRESHOLD`, `SUSPICIOUS_OVERRIDE_THRESHOLD`, `ENABLE_RULE_BASED_FALLBACK`
- **Risk scoring** (0-30 benign, 31-70 suspicious, 71-100 malicious)
- **Security recommendations** returned with every analysis
- **Structured logging** for AI analysis requests (label, confidence, rule hits, latency)
- **Input size limits** for text analysis endpoint (413 error for oversized input)
- **Configurable CORS origins** via `ALLOWED_ORIGINS` environment variable
- **Lightweight evaluation script** (`scripts/evaluate_hybrid.py`)
  - 60 labeled test samples (20 per class)
  - Accuracy, macro F1, per-class precision/recall, confusion matrix
  - JSON and Markdown reports saved to `reports/`
  - CPU-compatible, no GPU required
- **Unit tests** (`tests/test_hybrid.py`) — 30+ pytest tests
- **Architecture documentation** (`docs/architecture.md`) — Mermaid diagrams
- **Demo API requests** (`docs/demo_requests.md`) — 12 curl examples
- **Known limitations** documented in README

### Changed
- **AI analysis endpoints** (`/api/ai/analyze`, `/api/ai/analyze-batch`, `/api/ai/analyze-text`)
  - Now use hybrid detector
  - Added new response fields: `final_label`, `confidence`, `model_label`, `model_confidence`, `rule_label`, `rule_hits`, `explanation`, `risk_score`, `recommendation`
  - Backward compatible — old fields preserved
- **CORS middleware** — removed wildcard `*`, now uses `ALLOWED_ORIGINS`
- **Global exception handler** — returns JSON instead of stack traces
- **`requirements.txt`** — added `python-dotenv`

### Fixed
- Malicious class detection improved via rule-based fallback (no retraining needed)

## v2.0.0 — Initial TheKavach Release

- FastAPI backend with synthetic cybersecurity log generation
- SSE streaming for real-time log delivery
- HuggingFace MiniLM-based threat classifier (OMCHOKSI108/TheKavach)
- Log normalizer for structured-to-semantic conversion
- API key authentication middleware
- Dark-themed dashboard (frontend/index.html)
- Docker/Render deployment support
- 6-million-row chunked dataset with lazy loading
- Model evaluation script (eval_model.py) — 79.8% accuracy
