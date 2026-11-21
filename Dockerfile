FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend backend
COPY signatures signatures
ENV AEGIS_DATA_DIR=/data
VOLUME /data
WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "aegis.api:app", "--host", "0.0.0.0", "--port", "8000"]
