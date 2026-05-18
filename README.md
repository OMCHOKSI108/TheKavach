# TheKavach - AI Cybersecurity Threat Intelligence Platform

TheKavach is a synthetic cybersecurity telemetry streaming platform that generates
real-time network security logs and analyzes them using AI. Instead of providing
static CSV datasets for download, TheKavach operates as a live data infrastructure
service where developers, researchers, and ML engineers can obtain personalized
API keys and consume continuously generated firewall, network, ICMP, TCP, and
application logs. The platform transforms a 6-million-row cybersecurity dataset
into a dynamic simulation environment that mirrors how modern Security Operations
Centers (SOCs) and SIEM systems operate in enterprise settings.

The system is built on FastAPI for high-performance async-ready API delivery,
uses a chunked data loading architecture to maintain minimal memory footprint
suitable for free-tier cloud hosting, and integrates a MiniLM-based AI threat
classification model trained on the original dataset. The AI engine normalizes
raw log entries into semantic text, classifies threats as benign, suspicious,
or malicious, assigns severity scores, and provides explainable reasoning for
each prediction. The entire application is containerized with Docker and
deployment-ready on Render, HuggingFace Spaces, or any cloud platform.

## Architecture Overview

The platform follows a modular architecture designed for simplicity and future
scalability. The backend consists of a FastAPI application that serves three
primary functions: synthetic log generation, API key management, and AI-powered
threat analysis. The log generation engine produces randomized security events
by mutating timestamps, IP addresses, traffic sizes, protocols, and threat
labels derived from the original dataset patterns. The AI analysis pipeline
uses a normalization engine that converts structured log fields into canonical
semantic sentences, which are then processed by a fine-tuned MiniLM transformer
model for threat classification.

The frontend is a minimal dark-themed web interface built with HTML, TailwindCSS,
and vanilla JavaScript. It provides a landing page with API key generation, a
live log viewer with real-time streaming via Server-Sent Events, comprehensive
API documentation with code examples in multiple languages, and an interactive
AI log analysis widget. The design intentionally avoids heavy frameworks and
build steps, keeping the frontend lightweight and directly servable by the
FastAPI backend.

Data loading uses a lazy chunk-swapping strategy where only two 200,000-row CSV
chunks are held in memory at any time. When a request requires data from a
different chunk, the system evicts the oldest loaded chunk and loads the new
one. This approach reduces memory usage from approximately 2-3 gigabytes for
the full dataset to under 100 megabytes, making the platform viable on Render's
free tier with 512MB RAM limits. The Docker image includes only four chunks by
default, further reducing the container size for deployment.

## Project Structure

The project is organized into clearly separated modules for maintainability.
The backend directory contains the FastAPI application entry point, API route
handlers split between core endpoints and AI analysis endpoints, authentication
middleware for API key validation, a log generator that produces synthetic
security events, and a data loader that manages chunked CSV files. The models
directory houses the AI inference engine including the log normalizer that
converts raw log fields into semantic text, the threat intelligence engine
that wraps the HuggingFace transformer pipeline with severity scoring and
explainability logic, and a Gradio-based application template for HuggingFace
Spaces deployment.

The frontend directory contains three HTML files: the main landing page with
API key generation and AI analysis widget, the API documentation page with
tabbed code examples for cURL, Python, Node.js, and C++, and the live log
viewer that connects to the SSE streaming endpoint. The notebooks directory
holds the comprehensive 10-step Jupyter notebook that guides users through
dataset exploration, log normalization, data cleaning, feature engineering,
transformer training with MiniLM, severity engine construction, SHAP-based
explainability, ONNX optimization, and HuggingFace model deployment. The
dataset directory contains the original 834MB CSV file excluded from Git and
thirty 25MB chunk files that are Git-compatible.

`
TheKavach/
├── backend/
│   ├── main.py                 # FastAPI app entry point
│   ├── api/
│   │   ├── routes.py           # Core API endpoints
│   │   ├── ai_routes.py        # AI analysis endpoints
│   │   └── auth.py             # API key middleware
│   ├── generators/
│   │   ├── log_generator.py    # Synthetic log engine
│   │   └── data_loader.py      # Lazy chunk loader
│   ├── models/
│   │   └── schemas.py          # Pydantic models
│   └── requirements.txt
├── frontend/
│   ├── index.html              # Landing page + AI widget
│   ├── docs.html               # API documentation
│   └── viewer.html             # Live log viewer
├── models/
│   ├── inference.py            # AI inference engine
│   ├── app.py                  # HuggingFace Space (Gradio)
│   └── requirements.txt
├── notebooks/
│   └── 01_cybersecurity_threat_intelligence.ipynb
├── dataset/
│   └── chunks/                 # 30 x 25MB CSV files
├── Dockerfile
├── render.yaml
└── README.md
`

## Dataset and Chunking Strategy

The original cybersecurity dataset contains 6 million log entries across ten
columns including timestamp, source IP, destination IP, protocol, action,
threat label, log type, bytes transferred, user agent, and request path.
At 834MB, this file exceeds GitHub's 100MB per-file limit and would consume
excessive memory if loaded entirely. The solution splits the dataset into
thirty approximately 28MB chunk files, each containing 200,000 rows. These
chunks are small enough to push to GitHub individually and can be loaded
selectively at runtime.

The lazy loading system discovers all available chunk files at startup and
loads only the first two into memory. When a request needs data from a chunk
that is not currently loaded, the system removes the oldest loaded chunk from
memory and loads the requested one. This swap mechanism ensures that memory
usage stays constant regardless of the total number of chunks. The total row
count is calculated from the known rows-per-chunk multiplied by the number of
discovered chunks, avoiding the need to load all data just to report statistics.

## API Endpoints

The platform exposes a RESTful API under the /api prefix with authentication
via Bearer tokens. The POST /api/generate-key endpoint accepts a user name
and returns a unique API key prefixed with tk_. This key must be included
in the Authorization header for all subsequent requests except health checks
and status queries.

The GET /api/logs endpoint returns a batch of synthetic log entries with
optional filtering by threat label, log type, and protocol. The count
parameter controls the number of entries returned, ranging from 1 to 500.

The GET /api/stream endpoint provides Server-Sent Events for continuous
real-time log streaming. Clients connect once and receive log entries at
a configurable interval between 0.1 and 10 seconds. The threat_label query
parameter filters the stream to only emit entries matching a specific threat
level.

The GET /api/health endpoint returns the system status, total dataset rows,
and uptime without requiring authentication. The GET /api/status endpoint
provides detailed metrics including formatted uptime, dataset column names,
total rows, API key count, platform version, and timestamps. The GET /api/stats
endpoint returns distribution statistics for threat labels, protocols, and
log types computed across all available chunks.

### AI Analysis Endpoints

The AI analysis endpoints are grouped under /api/ai. The POST /api/ai/analyze
endpoint accepts a structured log object with protocol, action, user agent,
request path, bytes transferred, and log type fields. It normalizes the log
into semantic text, runs it through the MiniLM classifier, and returns the
predicted threat level, confidence score, severity rating, all class
probabilities, and an explanation of why the log was flagged.

The POST /api/ai/analyze-batch endpoint accepts up to 100 logs and returns
analysis results for each. The POST /api/ai/analyze-text endpoint accepts
pre-normalized text directly for classification. The GET /api/ai/status
endpoint reports whether the AI model is loaded and available, showing the
HuggingFace model name and a list of capabilities.

## AI Threat Intelligence Engine

The AI component transforms TheKavach from a simple log generator into a
semantic cybersecurity intelligence system. The pipeline begins with the
LogNormalizer class, which converts structured log fields into natural
language sentences. For example, a log with protocol TCP, action blocked,
user agent Nmap Scripting Engine, request path /admin/config, and bytes
transferred 45000 becomes the sentence:

> Blocked TCP connection detected by firewall log using nmap scanner
> targeting high-risk path with large data transfer.

This normalization is critical because it allows the transformer model to
understand cybersecurity concepts semantically rather than as isolated
categorical values. The normalizer maps protocols to descriptive phrases,
identifies security scanners by matching user agent strings against a known
list including Nmap, SQLMap, Nikto, and others, classifies request paths
into risk categories based on suspicious patterns like admin, config,
backup, and login endpoints, and categorizes data transfer volumes into
qualitative descriptions.

The ThreatIntelligenceEngine wraps a HuggingFace text classification pipeline
built on the all-MiniLM-L6-v2 model, which is a lightweight transformer with
approximately 22 million parameters. The model is fine-tuned to classify
normalized log text into three categories: benign representing normal network
traffic, suspicious representing anomalous but not definitively malicious
activity, and malicious representing confirmed threat behavior.

The engine computes severity scores by combining the predicted threat category
with the confidence level. A malicious prediction with over 95 percent
confidence receives a Critical severity rating, while lower confidence
predictions receive proportionally reduced severity. The engine also generates
human-readable explanations by analyzing the normalized text for indicators
such as scanner detection, blocked actions, high-risk path targeting,
authentication endpoint access, and unusual data transfer volumes.

## Training the AI Model

The training process is documented in the notebook
notebooks/01_cybersecurity_threat_intelligence.ipynb, which implements a
complete 10-step roadmap:

**Step 1** explores the dataset to understand attack patterns, protocol
distributions, action frequencies, and the distinguishing characteristics
between malicious and benign logs.

**Step 2** builds the LogNormalizer engine that converts raw logs into
semantic text suitable for NLP processing.

**Step 3** cleans the data by removing null values and duplicates, then
maps threat labels to integer classes (benign=0, suspicious=1, malicious=2).

**Step 4** adds structured features including logarithmic byte counts,
protocol encodings, path depth measurements, path risk scores, scanner
detection flags, user agent entropy calculations, and hour-of-day indicators.

**Step 5** tokenizes the normalized text using the MiniLM tokenizer with a
maximum length of 128 tokens and splits the data into training and test sets
with stratified sampling.

**Step 6** fine-tunes the MiniLM model using the HuggingFace Trainer API
with a learning rate of 2e-5, batch size of 32, three training epochs, and
FP16 mixed precision for faster training on GPU.

**Step 7** implements the severity and confidence engine that converts raw
predictions into SOC-style intelligence reports with prioritization.

**Step 8** trains a Random Forest classifier on the structured features and
uses SHAP to provide feature-level explainability for why specific logs
are flagged as threats.

**Step 9** exports the trained model to ONNX format for optimized inference
and benchmarks throughput to measure inference speed.

**Step 10** creates the production inference function and prepares the model
for HuggingFace Hub upload with a model card and configuration.

After training in Google Colab or Kaggle, the model is pushed to HuggingFace
as OMCHOKSI108/CyberKavach. The platform automatically downloads and uses
this model when the AI analysis endpoints are called.

## Deployment

The platform is designed for one-click deployment on Render using the
included render.yaml blueprint. The Dockerfile builds a lightweight image
based on python:3.11-slim that installs only the core dependencies and
copies four dataset chunks. The total image size is optimized to stay
within Render's build limits.

The render.yaml configuration specifies Docker as the build environment,
sets the health check path to /api/health, and configures the free tier
plan. Deployment requires pushing the code to a GitHub repository and
connecting it to Render, which automatically detects the render.yaml file
and builds the container.

For local development, the platform can be started with a single uvicorn
command after installing the requirements. Docker Compose is also available
for containerized local testing. The AI model is not required for the core
platform to function. The log generation, streaming, and API key management
endpoints work without any ML dependencies.

## Quick Start

Install the backend dependencies using pip install -r backend/requirements.txt
from the project root directory. Start the server with the command:

`ash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
`

The web interface is available at http://localhost:8000, the API documentation
at http://localhost:8000/docs, the live log viewer at http://localhost:8000/viewer,
and the Swagger UI at http://localhost:8000/api/docs.

Generate an API key through the web interface or by sending a POST request
to /api/generate-key with your name in the request body. Use the generated
key in the Authorization header as Bearer tk_your_key for all authenticated
endpoints.

To train the AI model, open the notebook in Google Colab, connect to a GPU
runtime, and execute all cells sequentially. After the model is pushed to
HuggingFace, restart the platform server and the AI analysis endpoints will
automatically download and use the trained model.

## Technology Stack

The backend uses FastAPI for the web framework, providing automatic OpenAPI
documentation, async request handling, and Pydantic-based data validation.
Pandas handles CSV data loading and manipulation with the custom chunk-swapping
loader. The AI pipeline uses HuggingFace Transformers for the MiniLM model,
PyTorch for tensor operations, and scikit-learn for the Random Forest
explainer and train-test splitting. SHAP provides feature importance
visualization for structured feature analysis. ONNX enables model export
for optimized inference in production environments.

The frontend uses vanilla HTML with TailwindCSS loaded from CDN for styling,
requiring no build step or Node.js dependencies. Server-Sent Events provide
real-time log streaming without the complexity of WebSocket connections. The
Docker container uses python:3.11-slim as the base image to minimize size
and attack surface. Render handles container orchestration, health checking,
and automatic HTTPS certificate provisioning.

## Future Roadmap

The platform is designed to evolve from its current MVP state into a
comprehensive cyber data infrastructure. Planned upgrades include WebSocket-based
bidirectional real-time streaming for interactive threat simulation, dedicated
threat simulation modes that generate DDoS, malware, phishing, and brute force
attack patterns with realistic timing and behavior, and multi-source telemetry
generation that produces Windows event logs, DNS query logs, cloud access logs,
and email security logs.

A Kafka-based high-throughput pipeline would replace the current REST API for
scenarios requiring millions of events per second, enabling integration with
enterprise SIEM systems. User dashboards with analytics would provide
visualization of threat trends, attack frequency over time, and geographic
IP distribution. Model benchmarking capabilities would allow researchers to
compare different ML models on the same synthetic dataset with standardized
metrics.

## License

MIT License. Use freely for research, education, and portfolio projects.
