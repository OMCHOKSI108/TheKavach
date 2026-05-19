# TheKavach - AI Cybersecurity Threat Intelligence Platform

[![Kaggle](https://kaggle.com/static/images/open-in-kaggle.svg)](https://www.kaggle.com/code/omchoksi04/thekavach)

TheKavach is a synthetic cybersecurity telemetry streaming platform that generates real-time network security logs and analyzes them using AI. Instead of providing static CSV datasets, it operates as a live data service where developers and ML engineers obtain API keys and consume continuously generated firewall, network, and application logs. The platform transforms a 6-million-row dataset into a dynamic simulation environment mirroring how modern SOCs and SIEM systems operate.

| Feature | Detail |
|---------|--------|
| Dataset | 6 million cybersecurity log entries |
| AI Model | MiniLM (all-MiniLM-L6-v2) fine-tuned for threat classification |
| Backend | FastAPI with async support |
| Frontend | HTML + TailwindCSS (no build step) |
| Memory | Lazy chunk loading (~100MB vs 2-3GB full load) |
| Deployment | Docker + Render (free tier compatible) |
| Streaming | Server-Sent Events for real-time logs |

## Architecture

`
Raw Logs → LogNormalizer → Semantic Text → MiniLM → Threat Class → Severity → API
                                                        ↓
                                                benign/suspicious/malicious
`

The platform has three core layers:

| Layer | Responsibility | Tech |
|-------|---------------|------|
| Data | Chunked CSV loading, lazy swap | Pandas |
| API | REST endpoints, SSE streaming, auth | FastAPI |
| AI | Log normalization, threat classification | HuggingFace Transformers |

## Project Structure

```
TheKavach/
├── backend/
│   ├── main.py                 # FastAPI app entry, serves frontend
│   ├── api/
│   │   ├── routes.py           # Core endpoints (logs, stream, health, status)
│   │   ├── ai_routes.py        # AI analysis endpoints
│   │   └── auth.py             # API key middleware
│   ├── generators/
│   │   ├── log_generator.py    # Synthetic log generation engine
│   │   └── data_loader.py      # Lazy chunk-swapping CSV loader
│   ├── models/
│   │   └── schemas.py          # Pydantic request/response models
│   └── requirements.txt        # Core dependencies
├── frontend/
│   ├── index.html              # Landing page + API key gen + AI widget
│   ├── docs.html               # API docs with multi-language examples
│   └── viewer.html             # Live SSE log viewer
├── models/
│   ├── inference.py            # AI inference engine (normalizer + classifier)
│   ├── app.py                  # HuggingFace Space (Gradio interface)
│   └── requirements.txt        # AI dependencies
├── notebooks/
│   └── 01_cybersecurity_threat_intelligence.ipynb  # 10-step training guide
├── dataset/
│   └── chunks/                 # 30 x 25MB CSV files (Git-compatible)
├── Dockerfile                  # Optimized container (4 chunks only)
├── render.yaml                 # Render deployment blueprint
└── README.md
```


## API Endpoints

### Core Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/generate-key | No | Generate API key from name |
| GET | /api/logs | Yes | Fetch batch of synthetic logs |
| GET | /api/stream | Yes | SSE real-time log streaming |
| GET | /api/health | No | System health check |
| GET | /api/status | No | Uptime, dataset info, metrics |
| GET | /api/stats | Yes | Threat/protocol distributions |

### AI Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/ai/analyze | No | Analyze single log entry |
| POST | /api/ai/analyze-batch | No | Analyze up to 100 logs |
| POST | /api/ai/analyze-text | No | Analyze pre-normalized text |
| GET | /api/ai/status | No | Check AI model availability |

### Query Parameters

| Parameter | Endpoint | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| count | /logs | int | 50 | Number of logs (1-500) |
| 	hreat_label | /logs, /stream | string | - | Filter: benign, suspicious, malicious |
| log_type | /logs | string | - | Filter: firewall, ids, application |
| protocol | /logs | string | - | Filter: TCP, UDP, HTTP, HTTPS, etc. |
| interval | /stream | float | 1.0 | Seconds between entries (0.1-10) |

## Quick Start

### Local Development

`ash
# Install dependencies
pip install -r backend/requirements.txt

# Start server
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
`

| URL | Purpose |
|-----|---------|
| http://localhost:8000 | Landing page + AI widget |
| http://localhost:8000/docs | API documentation |
| http://localhost:8000/viewer | Live log viewer |
| http://localhost:8000/api/docs | Swagger UI |

### Generate API Key

`ash
curl -X POST http://localhost:8000/api/generate-key \
  -H "Content-Type: application/json" \
  -d '{"name": "Your Name"}'
`

### Fetch Logs

`ash
curl "http://localhost:8000/api/logs?count=50&threat_label=malicious" \
  -H "Authorization: Bearer tk_your_key"
`

### AI Analysis

`ash
# TheKavach - AI Cybersecurity Threat Intelligence Platform

[![Kaggle](https://kaggle.com/static/images/open-in-kaggle.svg)](https://www.kaggle.com/code/omchoksi04/thekavach)

TheKavach is a synthetic cybersecurity telemetry streaming platform that generates real-time network security logs and analyzes them with AI. It provides a live data service (via API keys) that streams continuously generated firewall, network, and application logs. The platform converts a large static CSV dataset into a dynamic simulation environment that mirrors modern SOC/SIEM workflows.

| Feature     | Detail                                                   |
|-------------|----------------------------------------------------------|
| Dataset     | ~6 million cybersecurity log entries                     |
| AI Model    | MiniLM (all-MiniLM-L6-v2) fine-tuned for threat classification |
| Backend     | FastAPI (async)                                          |
| Frontend    | Static HTML + TailwindCSS (no build step)               |
| Memory      | Lazy chunk loading (small memory footprint)              |
| Deployment  | Docker + Render                                          |
| Streaming   | Server-Sent Events for real-time logs                    |

## Architecture

```
Raw Logs → LogNormalizer → Semantic Text → MiniLM → Threat Class → Severity → API
                                          ↓
                              benign / suspicious / malicious
```

The platform has three core layers:

| Layer | Responsibility                          | Tech                         |
|-------|-----------------------------------------|------------------------------|
| Data  | Chunked CSV loading, lazy swap          | pandas                       |
| API   | REST endpoints, SSE streaming, auth     | FastAPI                      |
| AI    | Log normalization, threat classification| Hugging Face Transformers    |

## Project Structure

```
TheKavach/
├── backend/
│   ├── main.py                 # FastAPI app entry, serves frontend
│   ├── api/
│   │   ├── routes.py           # Core endpoints (logs, stream, health, status)
│   │   ├── ai_routes.py        # AI analysis endpoints
│   │   └── auth.py             # API key middleware
│   ├── generators/
│   │   ├── log_generator.py    # Synthetic log generation engine
│   │   └── data_loader.py      # Lazy chunk-swapping CSV loader
│   ├── models/
│   │   └── schemas.py          # Pydantic request/response models
│   └── requirements.txt        # Core dependencies
├── frontend/
│   ├── index.html              # Landing page + API key gen + AI widget
│   ├── docs.html               # API docs with multi-language examples
│   └── viewer.html             # Live SSE log viewer
├── models/
│   ├── inference.py            # AI inference engine (normalizer + classifier)
│   ├── app.py                  # HuggingFace Space (Gradio interface)
│   └── requirements.txt        # AI dependencies
├── notebooks/
│   └── 01_cybersecurity_threat_intelligence.ipynb  # Training guide
├── dataset/
│   └── chunks/                 # CSV chunks (Git-compatible)
├── Dockerfile                  # Optimized container (4 chunks only)
├── render.yaml                 # Render deployment blueprint
└── README.md
```

## API Endpoints

### Core Endpoints

| Method | Path                 | Auth | Description                               |
|--------|----------------------|------|-------------------------------------------|
| POST   | /api/generate-key    | No   | Generate API key from a name              |
| GET    | /api/logs            | Yes  | Fetch batch of synthetic logs             |
| GET    | /api/stream          | Yes  | SSE real-time log streaming               |
| GET    | /api/health          | No   | System health check                       |
| GET    | /api/status          | No   | Uptime, dataset info, metrics             |
| GET    | /api/stats           | Yes  | Threat/protocol distributions             |

### AI Endpoints

| Method | Path                   | Auth | Description                     |
|--------|------------------------|------|---------------------------------|
| POST   | /api/ai/analyze        | No   | Analyze single log entry        |
| POST   | /api/ai/analyze-batch  | No   | Analyze up to 100 logs          |
| POST   | /api/ai/analyze-text   | No   | Analyze pre-normalized text     |
| GET    | /api/ai/status         | No   | Check AI model availability     |

### Query Parameters

| Parameter     | Endpoint         | Type  | Default | Description                                |
|---------------|------------------|-------|---------|--------------------------------------------|
| count         | /logs            | int   | 50      | Number of logs (1-500)                     |
| threat_label  | /logs, /stream   | str   | -       | Filter: benign, suspicious, malicious      |
| log_type      | /logs            | str   | -       | Filter: firewall, ids, application         |
| protocol      | /logs            | str   | -       | Filter: TCP, UDP, HTTP, HTTPS, etc.        |
| interval      | /stream          | float | 1.0     | Seconds between entries (0.1-10)           |

## Quick Start

### Local Development

```bash
# Install dependencies
pip install -r backend/requirements.txt

# Start server
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

| URL                            | Purpose                        |
|--------------------------------|--------------------------------|
| http://localhost:8000          | Landing page + AI widget       |
| http://localhost:8000/docs     | API documentation              |
| http://localhost:8000/viewer   | Live log viewer                |
| http://localhost:8000/api/docs | Swagger UI                     |

### Generate API Key

```bash
curl -X POST http://localhost:8000/api/generate-key \
  -H "Content-Type: application/json" \
  -d '{"name": "Your Name"}'
```

### Fetch Logs

```bash
curl "http://localhost:8000/api/logs?count=50&threat_label=malicious" \
  -H "Authorization: Bearer tk_your_key"
```

### AI Analysis

```bash
curl -X POST http://localhost:8000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "TCP",
    "action": "blocked",
    "user_agent": "Nmap Scripting Engine",
    "request_path": "/admin/config",
    "bytes_transferred": 45000,
    "log_type": "firewall"
  }'
```

### AI Response Format

```json
{
  "threat": "malicious",
  "confidence": 0.9652,
  "confidence_pct": "96.5%",
  "severity": "Critical",
  "all_scores": { "benign": 0.012, "suspicious": 0.023, "malicious": 0.965 },
  "explanation": [
    "Nmap scanner detected",
    "Request blocked/denied by security controls",
    "Targeting high-risk path (admin/config/backup)"
  ]
}
```

## AI Threat Intelligence

The AI pipeline converts raw structured logs into semantic text, then classifies them using a fine-tuned MiniLM transformer.

### Normalization Examples

| Raw Log Fields                         | Normalized Text                                                                 |
|----------------------------------------|----------------------------------------------------------------------------------|
| TCP, blocked, Nmap, /admin/config      | Blocked TCP connection detected by firewall log using nmap scanner targeting high-risk path |
| HTTP, allowed, Chrome, /login          | Permitted HTTP request recorded by application log accessing authentication path |
| HTTPS, blocked, SQLMap, /api/login     | Blocked HTTPS request detected by IDS using sqlmap scanner targeting authentication path |

### Threat Classification

| Label      | Meaning                         | Distribution |
|------------|---------------------------------|--------------|
| benign     | Normal network traffic          | ~70%         |
| suspicious | Anomalous but not confirmed     | ~20%         |
| malicious  | Confirmed threat behavior       | ~10%         |

### Severity Scoring

| Confidence | Malicious | Suspicious | Benign        |
|------------|-----------|------------|---------------|
| > 95%      | Critical  | High       | Low           |
| > 85%      | High      | Medium     | Low           |
| > 70%      | Medium    | Medium     | Informational |
| < 70%      | Informational | Informational | Informational |

## Training the AI Model

The complete training process is in `notebooks/01_cybersecurity_threat_intelligence.ipynb`.

| Step | Task                      | Output                                      |
|------|---------------------------|---------------------------------------------|
| 1    | Dataset exploration       | Attack patterns, distributions              |
| 2    | Log normalization engine  | Raw logs → semantic text                    |
| 3    | Data cleaning & labeling  | Clean dataset with integer labels           |
| 4    | Structured features       | Bytes, protocol, path risk, scanner flags   |
| 5    | Tokenization              | MiniLM tokens, train/test split             |
| 6    | Model training            | Fine-tuned MiniLM classifier                |
| 7    | Severity engine           | SOC-style intelligence reports              |
| 8    | SHAP explainability       | Feature importance analysis                 |
| 9    | ONNX optimization        | Fast inference export                        |
| 10   | HuggingFace upload        | Deployed model on HF Hub                    |

The platform automatically downloads and uses the model when AI endpoints are called.

## Memory Optimization

The original CSV is split into chunks. The lazy loader keeps a small number of chunks in memory to reduce RAM usage:

| Approach                        | Memory Usage | Load Time |
|---------------------------------|--------------|-----------|
| Load all rows                   | ~2-3 GB      | 30-60s    |
| Lazy chunk loading (2 chunks)   | ~56 MB       | 2-5s      |
| Docker (4 chunks in image)      | ~112 MB      | Instant   |

The Dockerfile copies only a small set of chunks to keep the container size manageable for Render's free tier.

## Deployment

### Render (Free Tier)

1. Push code to GitHub
2. Connect repository to https://render.com
3. Render auto-detects `render.yaml` and builds via Docker
4. Platform live at https://your-app.onrender.com

| Setting      | Value         |
|--------------|---------------|
| Build        | Docker        |
| Plan         | Free (512MB RAM) |
| Health Check | /api/health   |
| Port         | 8000          |

### Docker Compose (Local)

```bash
docker-compose -f docker/docker-compose.yml up --build
```

### HuggingFace Space

The `models/app.py` file provides a Gradio interface. Deploy by creating a new Space with the `models/` directory contents.

## Technology Stack

| Category  | Technology                     | Purpose                         |
|-----------|--------------------------------|---------------------------------|
| Backend   | FastAPI                        | REST API, async, auto docs      |
| Data      | pandas                         | CSV loading, chunk management   |
| AI        | Hugging Face Transformers      | MiniLM text classification      |
| AI        | PyTorch                        | Tensor operations               |
| AI        | scikit-learn                   | Random Forest explainer         |
| AI        | SHAP                           | Feature importance              |
| AI        | ONNX                           | Optimized inference             |
| Frontend  | HTML + TailwindCSS             | Dark-themed UI                  |
| Streaming | Server-Sent Events             | Real-time log delivery          |
| Container | Docker (python:3.11-slim)      | Portable deployment             |
| Cloud     | Render                         | Free-tier hosting               |

## License

MIT License. Use freely for research, education, and portfolio projects.

