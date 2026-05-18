from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from typing import Optional
import json
import asyncio
from datetime import datetime
from ..models.schemas import KeyRequest, KeyResponse, LogsResponse, HealthResponse
from ..api.auth import generate_api_key, api_key_store
from ..generators.log_generator import log_generator
from ..generators.data_loader import data_loader

router = APIRouter()
start_time = datetime.now()

@router.post("/generate-key", response_model=KeyResponse, tags=["Authentication"])
async def generate_key(request: KeyRequest):
    key = generate_api_key(request.name)
    return KeyResponse(
        api_key=key,
        name=request.name,
        created_at=datetime.now().isoformat(),
        message="API key generated successfully. Use it in the Authorization header as: Bearer <your-key>"
    )

@router.get("/logs", response_model=LogsResponse, tags=["Logs"])
async def get_logs(
    count: int = Query(default=50, ge=1, le=500, description="Number of log entries to return"),
    threat_label: Optional[str] = Query(default=None, description="Filter by threat label: benign, suspicious, malicious"),
    log_type: Optional[str] = Query(default=None, description="Filter by log type: firewall, network, application, ids"),
    protocol: Optional[str] = Query(default=None, description="Filter by protocol")
):
    logs = log_generator.generate_batch(count)
    if threat_label:
        logs = [l for l in logs if l["threat_label"] == threat_label]
    if log_type:
        logs = [l for l in logs if l["log_type"] == log_type]
    if protocol:
        logs = [l for l in logs if l["protocol"] == protocol]
    return LogsResponse(count=len(logs), logs=logs)

async def log_stream(threat_label: Optional[str] = None, interval: float = 1.0):
    while True:
        log = log_generator.generate_single_log()
        if threat_label and log["threat_label"] != threat_label:
            continue
        yield f"data: {json.dumps(log)}\n\n"
        await asyncio.sleep(interval)

@router.get("/stream", tags=["Streaming"])
async def stream_logs(
    threat_label: Optional[str] = Query(default=None, description="Filter by threat label"),
    interval: float = Query(default=1.0, ge=0.1, le=10.0, description="Seconds between log entries")
):
    return StreamingResponse(
        log_stream(threat_label=threat_label, interval=interval),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    uptime = datetime.now() - start_time
    return HealthResponse(
        status="healthy",
        dataset_rows=len(data_loader.get_dataframe()) if data_loader.get_dataframe() is not None else 0,
        uptime=str(uptime)
    )

@router.get("/status", tags=["System"])
async def get_status():
    uptime = datetime.now() - start_time
    total_seconds = int(uptime.total_seconds())
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    df = data_loader.get_dataframe()
    return {
        "status": "operational",
        "uptime": {
            "raw": str(uptime),
            "days": days,
            "hours": hours,
            "minutes": minutes,
            "seconds": seconds,
            "formatted": f"{days}d {hours}h {minutes}m {seconds}s"
        },
        "dataset": {
            "total_rows": len(df) if df is not None else 0,
            "columns": list(df.columns) if df is not None else []
        },
        "api_keys_generated": len(api_key_store),
        "version": "1.0.0",
        "started_at": start_time.isoformat(),
        "current_time": datetime.now().isoformat()
    }

@router.get("/stats", tags=["System"])
async def get_stats():
    df = data_loader.get_dataframe()
    return {
        "total_keys_generated": len(api_key_store),
        "dataset_columns": list(df.columns) if df is not None else [],
        "threat_distribution": data_loader.get_column_stats("threat_label"),
        "protocol_distribution": data_loader.get_column_stats("protocol"),
        "log_type_distribution": data_loader.get_column_stats("log_type")
    }
