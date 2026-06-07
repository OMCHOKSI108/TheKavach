# TheKavach Architecture

## System Overview

TheKavach is a layered AI cybersecurity telemetry platform with a hybrid ML + rule-based threat detection engine.

## High-Level Architecture

```mermaid
flowchart TB
    Client["Client / Dashboard"]
    API["FastAPI API Layer"]
    LogGen["Log Generator"]
    AIEnd["/api/ai/analyze Endpoint"]
    Norm["Log Normalizer"]
    ML["MiniLM Model Inference"]
    Rules["Rule-Based Security Heuristics"]
    Hybrid["Hybrid Decision Engine"]
    Risk["Risk Score + Explanation"]
    Response["API Response / Dashboard"]

    Client --> API
    API --> LogGen
    API --> AIEnd
    AIEnd --> Norm
    Norm --> ML
    ML --> Hybrid
    Rules --> Hybrid
    Hybrid --> Risk
    Risk --> Response
    Response --> Client
```

## Request Flow (Sequence Diagram)

```mermaid
sequenceDiagram
    participant User as Client / Dashboard
    participant API as FastAPI API
    participant Model as MiniLM Model
    participant Rules as Security Rules
    participant Hybrid as Hybrid Engine

    User->>API: POST /api/ai/analyze (log entry)
    API->>API: Validate input, check size limit
    API->>API: Normalize log to semantic text
    API->>Model: predict(normalized_text)
    Model-->>API: {threat, confidence, all_scores}
    API->>Rules: scan(normalized_text)
    Rules-->>API: {rule_hits, rule_weight, rule_label}
    API->>Hybrid: compare model vs rules
    Hybrid-->>API: {final_label, confidence, explanation}
    API->>API: compute risk_score, recommendation
    API-->>User: {final_label, confidence, explanation, ...}
```

## Layer Details

| Layer | Responsibility | Technology |
|-------|---------------|------------|
| Client | Browser UI, API consumers | HTML + TailwindCSS / curl |
| API | REST endpoints, SSE streaming, auth | FastAPI |
| Log Generator | Synthetic log generation | Python (randomized) |
| Normalizer | Convert raw logs to semantic text | LogNormalizer class |
| ML Inference | Text classification pipeline | HuggingFace MiniLM |
| Rule Engine | Pattern-based threat heuristics | Regex rules (100+) |
| Hybrid Decision | Merge ML + rules, explain | HybridDetector class |
| Risk Scoring | Numeric risk (0-100) | Category-based ranges |

## Key Design Decisions

1. **Hybrid approach**: Rule-based fallback compensates for ML class imbalance without retraining.
2. **No retraining required**: All malicious detection improvements come from the rule layer.
3. **Configurable thresholds**: All thresholds are environment-driven (see `.env.example`).
4. **Backward compatibility**: Old API fields are preserved; new fields are additive.
5. **Lightweight evaluation**: `scripts/evaluate_hybrid.py` runs on CPU without GPU/training dependencies.
