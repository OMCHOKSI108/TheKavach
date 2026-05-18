from pydantic import BaseModel, Field
from typing import Optional, List

class KeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="User name for API key generation")

class KeyResponse(BaseModel):
    api_key: str
    name: str
    created_at: str
    message: str

class LogEntry(BaseModel):
    id: str
    timestamp: str
    source_ip: str
    dest_ip: str
    protocol: str
    action: str
    threat_label: str
    log_type: str
    bytes_transferred: int
    user_agent: str
    request_path: str

class LogsResponse(BaseModel):
    count: int
    logs: List[LogEntry]

class HealthResponse(BaseModel):
    status: str
    dataset_rows: int
    uptime: str
