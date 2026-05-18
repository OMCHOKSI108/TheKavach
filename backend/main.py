from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import os
from .api.routes import router
from .api.ai_routes import router as ai_router
from .api.auth import api_key_middleware

app = FastAPI(
    title="TheKavach - AI Cybersecurity Threat Intelligence Platform",
    description="Real-time cybersecurity log streaming + AI threat detection API",
    version="2.0.0",
    contact={"name": "TheKavach Team"}
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(api_key_middleware)
app.include_router(router, prefix="/api")
app.include_router(ai_router, prefix="/api/ai")

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frontend_dir = os.path.join(base_dir, "frontend")

@app.get("/")
async def serve_frontend():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

@app.get("/docs")
async def serve_docs():
    return FileResponse(os.path.join(frontend_dir, "docs.html"))

@app.get("/viewer")
async def serve_viewer():
    return FileResponse(os.path.join(frontend_dir, "viewer.html"))

@app.get("/favicon.ico")
async def favicon():
    return FileResponse(os.path.join(frontend_dir, "favicon.ico")) if os.path.exists(os.path.join(frontend_dir, "favicon.ico")) else None
