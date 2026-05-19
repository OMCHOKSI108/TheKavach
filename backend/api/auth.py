import uuid
from datetime import datetime
from typing import Dict
from fastapi import Request, HTTPException

api_key_store: Dict[str, dict] = {}

def generate_api_key(name: str) -> str:
    key = f"tk_{uuid.uuid4().hex}"
    api_key_store[key] = {
        "name": name,
        "created_at": datetime.now().isoformat(),
        "request_count": 0
    }
    return key

async def api_key_middleware(request: Request, call_next):
    path = request.url.path

    public_prefixes = [
        "/api/health",
        "/api/generate-key",
        "/api/status",
        "/api/stats",
        "/api/stream",
        "/api/logs",
        "/api/ai/",
        "/api/docs",
        "/api/openapi.json",
        "/openapi.json",
        "/docs",
        "/viewer",
        "/favicon.ico",
    ]

    if path == "/" or any(path.startswith(p) for p in public_prefixes):
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing API key. Use: Authorization: Bearer <your-key>")

    key = auth_header.split(" ", 1)[1]
    if key not in api_key_store:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")

    api_key_store[key]["request_count"] += 1
    return await call_next(request)
