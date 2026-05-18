FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --compile -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY dataset/ ./dataset/

RUN python -c "import sys; sys.path.insert(0, '.'); from backend.generators.data_loader import data_loader; print(f'Dataset loaded: {len(data_loader.df)} rows')" || true

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
