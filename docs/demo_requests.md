# TheKavach Demo API Requests

Below are example `curl` commands to test various TheKavach API endpoints. Replace `http://localhost:8000` with your deployed URL as needed.

## Prerequisites

```bash
# Start the server locally
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

## 1. Health Check

```bash
curl http://localhost:8000/api/health
```

## 2. Generate an API Key

```bash
curl -X POST http://localhost:8000/api/generate-key \
  -H "Content-Type: application/json" \
  -d '{"name": "Demo User"}'
```

## 3. Benign Log Analysis

```bash
curl -X POST http://localhost:8000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "HTTP",
    "action": "allowed",
    "user_agent": "Mozilla/5.0 Chrome/120",
    "request_path": "/index.html",
    "bytes_transferred": 1200,
    "log_type": "application"
  }'
```

## 4. Suspicious Login Failure

```bash
curl -X POST http://localhost:8000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "HTTP",
    "action": "blocked",
    "user_agent": "python-requests/2.31.0",
    "request_path": "/login",
    "bytes_transferred": 450,
    "log_type": "application"
  }'
```

## 5. SQL Injection Attack

```bash
curl -X POST http://localhost:8000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "HTTP",
    "action": "blocked",
    "user_agent": "SQLMap/1.6-dev",
    "request_path": "/api/login?id=1 OR 1=1",
    "bytes_transferred": 2500,
    "log_type": "ids"
  }'
```

## 6. XSS Attack

```bash
curl -X POST http://localhost:8000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "HTTP",
    "action": "blocked",
    "user_agent": "Mozilla/5.0",
    "request_path": "/search?q=<script>alert(1)</script>",
    "bytes_transferred": 800,
    "log_type": "ids"
  }'
```

## 7. Path Traversal Attempt

```bash
curl -X POST http://localhost:8000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "HTTP",
    "action": "blocked",
    "user_agent": "curl/7.64.1",
    "request_path": "/../../etc/passwd",
    "bytes_transferred": 300,
    "log_type": "ids"
  }'
```

## 8. Batch Analysis

```bash
curl -X POST http://localhost:8000/api/ai/analyze-batch \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {
        "protocol": "HTTP",
        "action": "allowed",
        "user_agent": "Mozilla/5.0 Chrome/120",
        "request_path": "/index.html",
        "bytes_transferred": 1200,
        "log_type": "application"
      },
      {
        "protocol": "TCP",
        "action": "blocked",
        "user_agent": "Nmap Scripting Engine",
        "request_path": "/admin/config",
        "bytes_transferred": 45000,
        "log_type": "firewall"
      },
      {
        "protocol": "HTTP",
        "action": "blocked",
        "user_agent": "SQLMap/1.6-dev",
        "request_path": "/api/login?id=1 OR 1=1",
        "bytes_transferred": 2500,
        "log_type": "ids"
      }
    ]
  }'
```

## 9. Raw Text Analysis

```bash
curl -X POST http://localhost:8000/api/ai/analyze-text \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Blocked TCP connection detected by firewall log using nmap scanner targeting high-risk path with large data transfer."
  }'
```

## 10. SSE Log Stream

```bash
# Stream all logs (real-time)
curl -N http://localhost:8000/api/stream

# Stream only malicious logs every 2 seconds
curl -N "http://localhost:8000/api/stream?threat_label=malicious&interval=2.0"
```

## 11. Fetch Logs

```bash
# Fetch 10 recent logs
curl "http://localhost:8000/api/logs?count=10"

# Fetch malicious firewall logs
curl "http://localhost:8000/api/logs?count=20&threat_label=malicious&log_type=firewall"
```

## 12. System Status

```bash
curl http://localhost:8000/api/status
curl http://localhost:8000/api/stats
curl http://localhost:8000/api/ai/status
```
