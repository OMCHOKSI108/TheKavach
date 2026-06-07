import logging
import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List

from ..core.config import (
    MODEL_HIGH_CONFIDENCE_THRESHOLD,
    MALICIOUS_OVERRIDE_THRESHOLD,
    SUSPICIOUS_OVERRIDE_THRESHOLD,
    ENABLE_RULE_BASED_FALLBACK,
    HF_MODEL_ID,
    MAX_TEXT_INPUT_LENGTH,
)

logger = logging.getLogger("thekavach.ai")

router = APIRouter()


class LogAnalysisRequest(BaseModel):
    protocol: str = Field(..., description="Network protocol")
    action: str = Field(..., description="Action taken")
    user_agent: str = Field(default="", description="User agent string")
    request_path: str = Field(default="/", description="Request path")
    bytes_transferred: int = Field(default=0, description="Bytes transferred")
    log_type: str = Field(default="firewall", description="Log source type")
    source_ip: str = Field(default="", description="Source IP")
    dest_ip: str = Field(default="", description="Destination IP")


class BatchAnalysisRequest(BaseModel):
    logs: List[LogAnalysisRequest] = Field(..., min_items=1, max_items=100)


class TextAnalysisRequest(BaseModel):
    text: str = Field(..., description="Normalized log text", max_length=MAX_TEXT_INPUT_LENGTH)


def get_ai_engine():
    try:
        import sys, os as os_mod
        project_root = os_mod.path.dirname(os_mod.path.dirname(os_mod.path.dirname(os_mod.path.abspath(__file__))))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from models.inference import CybersecurityAI
        return CybersecurityAI(hf_model=HF_MODEL_ID)
    except Exception as e:
        logger.warning(f"AI model not available: {e}")
        return None


def get_hybrid_detector():
    try:
        import sys, os as os_mod
        project_root = os_mod.path.dirname(os_mod.path.dirname(os_mod.path.dirname(os_mod.path.abspath(__file__))))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from models.hybrid_detector import HybridDetector
        return HybridDetector(
            model_high_confidence_threshold=MODEL_HIGH_CONFIDENCE_THRESHOLD,
            malicious_override_threshold=MALICIOUS_OVERRIDE_THRESHOLD,
            suspicious_override_threshold=SUSPICIOUS_OVERRIDE_THRESHOLD,
            enable_rule_fallback=ENABLE_RULE_BASED_FALLBACK,
        )
    except Exception as e:
        logger.warning(f"Hybrid detector not available: {e}")
        return None


def run_hybrid_analysis(engine, normalized_text: str) -> dict:
    start = time.time()
    model_result = engine.predict(normalized_text)
    model_latency = (time.time() - start) * 1000

    detector = get_hybrid_detector()
    if detector:
        hybrid_result = detector.analyze(model_result, normalized_text)
    else:
        model_result["final_label"] = model_result.get("threat", "benign")
        model_result["model_label"] = model_result.get("threat", "benign")
        model_result["model_confidence"] = model_result.get("confidence", 0.0)
        model_result["rule_label"] = "benign"
        model_result["rule_hits"] = []
        model_result["risk_score"] = 0
        model_result["recommendation"] = "No additional analysis available."
        model_result["latency_ms"] = round(model_latency, 2)
        hybrid_result = model_result

    total_latency = (time.time() - start) * 1000
    hybrid_result["latency_ms"] = round(total_latency, 2)

    logger.info(
        f"AI analysis | label={hybrid_result.get('final_label')} "
        f"conf={hybrid_result.get('confidence', 0):.3f} "
        f"rules={hybrid_result.get('rule_hits', [])} "
        f"lat={total_latency:.1f}ms"
    )
    return hybrid_result


@router.post("/analyze", tags=["AI Analysis"])
async def analyze_log(request: LogAnalysisRequest):
    engine = get_ai_engine()
    if not engine:
        raise HTTPException(
            status_code=503,
            detail="AI model not loaded. Train model and push to HuggingFace as OMCHOKSI108/TheKavach",
        )
    try:
        raw_log = request.model_dump()
        normalized = engine.normalizer.normalize(raw_log)
        result = run_hybrid_analysis(engine, normalized)
        result["raw_log"] = raw_log
        result["normalized_text"] = normalized
        return result
    except Exception as e:
        logger.error(f"Analyze error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-batch", tags=["AI Analysis"])
async def analyze_batch(request: BatchAnalysisRequest):
    engine = get_ai_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="AI model not loaded")
    try:
        results = []
        for log in request.logs:
            raw = log.model_dump()
            normalized = engine.normalizer.normalize(raw)
            hybrid = run_hybrid_analysis(engine, normalized)
            hybrid["raw_log"] = raw
            hybrid["normalized_text"] = normalized
            results.append(hybrid)
        return {"count": len(results), "results": results}
    except Exception as e:
        logger.error(f"Batch analyze error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-text", tags=["AI Analysis"])
async def analyze_text(request: TextAnalysisRequest):
    engine = get_ai_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="AI model not loaded")
    try:
        if len(request.text) > MAX_TEXT_INPUT_LENGTH:
            raise HTTPException(
                status_code=413,
                detail=f"Input text too long ({len(request.text)} chars). Maximum is {MAX_TEXT_INPUT_LENGTH}.",
            )
        result = run_hybrid_analysis(engine, request.text)
        result["input_text"] = request.text
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Text analyze error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status", tags=["AI Analysis"])
async def ai_status():
    engine = get_ai_engine()
    detector = get_hybrid_detector()
    available = engine is not None
    return {
        "available": available,
        "model": HF_MODEL_ID if available else None,
        "hybrid_detector": detector is not None,
        "thresholds": {
            "model_high_confidence": MODEL_HIGH_CONFIDENCE_THRESHOLD,
            "malicious_override": MALICIOUS_OVERRIDE_THRESHOLD,
            "suspicious_override": SUSPICIOUS_OVERRIDE_THRESHOLD,
            "rule_fallback_enabled": ENABLE_RULE_BASED_FALLBACK,
        },
        "capabilities": [
            "Single log analysis",
            "Batch log analysis (up to 100)",
            "Raw text analysis",
            "Threat classification (benign/suspicious/malicious)",
            "Hybrid ML + rule-based detection",
            "Severity scoring",
            "Confidence levels",
            "Explainable predictions",
            "Risk scoring",
            "Security recommendations",
        ] if available else [],
        "note": "Run notebooks/Final.ipynb in Colab, then push model to OMCHOKSI108/TheKavach on HuggingFace" if not available else None,
    }
