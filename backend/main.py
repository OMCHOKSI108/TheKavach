from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import os
import logging
from .api.routes import router
from .api.ai_routes import router as ai_router
from .api.auth import api_key_middleware
from .core.config import ALLOWED_ORIGINS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("thekavach")

app = FastAPI(
    title="TheKavach - AI Cybersecurity Threat Intelligence Platform",
    description="Real-time cybersecurity log streaming + AI threat detection API with hybrid ML + rule-based inference",
    version="2.1.0",
    contact={"name": "TheKavach Team"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(api_key_middleware)

app.include_router(router, prefix="/api")
app.include_router(ai_router, prefix="/api/ai")

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frontend_dir = os.path.join(base_dir, "frontend")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."},
    )


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
    path = os.path.join(frontend_dir, "favicon.ico")
    if os.path.exists(path):
        return FileResponse(path)
    return None
