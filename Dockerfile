# ==============================================================================
# ZeroTrust-Enclave: SPIFFE Workload Attestation & Policy Gateway Server
# ==============================================================================
FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY zerotrust ./zerotrust
RUN pip install --no-cache-dir -e .

EXPOSE 8443

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

ENTRYPOINT ["zerotrust", "serve", "--host", "0.0.0.0", "--port", "8443"]
