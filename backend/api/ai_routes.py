from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List

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
    text: str = Field(..., description="Normalized log text")

def get_ai_engine():
    try:
        import sys, os
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from models.inference import CybersecurityAI
        return CybersecurityAI(hf_model="OMCHOKSI108/CyberKavach")
    except Exception as e:
        return None

@router.post("/analyze", tags=["AI Analysis"])
async def analyze_log(request: LogAnalysisRequest):
    engine = get_ai_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="AI model not loaded. Train model and push to HuggingFace as OMCHOKSI108/CyberKavach")
    try:
        result = engine.analyze_log(request.model_dump())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze-batch", tags=["AI Analysis"])
async def analyze_batch(request: BatchAnalysisRequest):
    engine = get_ai_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="AI model not loaded")
    try:
        results = [engine.analyze_log(log.model_dump()) for log in request.logs]
        return {"count": len(results), "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze-text", tags=["AI Analysis"])
async def analyze_text(request: TextAnalysisRequest):
    engine = get_ai_engine()
    if not engine:
        raise HTTPException(status_code=503, detail="AI model not loaded")
    try:
        result = engine.engine.predict(request.text)
        result["input_text"] = request.text
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status", tags=["AI Analysis"])
async def ai_status():
    engine = get_ai_engine()
    available = engine is not None
    return {
        "available": available,
        "model": "OMCHOKSI108/CyberKavach" if available else None,
        "capabilities": [
            "Single log analysis",
            "Batch log analysis (up to 100)",
            "Raw text analysis",
            "Threat classification (benign/suspicious/malicious)",
            "Severity scoring",
            "Confidence levels",
            "Explainable predictions"
        ] if available else [],
        "note": "Run notebooks/01_cybersecurity_threat_intelligence.ipynb in Colab, then push model to OMCHOKSI108/CyberKavach on HuggingFace" if not available else None
    }
