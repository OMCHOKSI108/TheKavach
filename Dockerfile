FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --compile -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Only copy 4 chunks for stats (~112MB) instead of all 30
COPY dataset/chunks/data_chunk_000.csv ./dataset/chunks/data_chunk_000.csv
COPY dataset/chunks/data_chunk_001.csv ./dataset/chunks/data_chunk_001.csv
COPY dataset/chunks/data_chunk_002.csv ./dataset/chunks/data_chunk_002.csv
COPY dataset/chunks/data_chunk_003.csv ./dataset/chunks/data_chunk_003.csv

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
