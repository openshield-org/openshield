FROM python:3.11-slim-trixie

WORKDIR /app

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Set INSTALL_AI_DEPS=true at build time to include the optional RAG pipeline
# (chromadb + numpy). Excluded by default: chromadb has active CVEs with no
# upstream fix (CVE-2026-45830, CVE-2026-45833). AI routes return 503 without
# this; the API server and all other functionality are unaffected.
ARG INSTALL_AI_DEPS=false

COPY requirements.txt requirements-ai.txt ./
RUN pip install --no-cache-dir --upgrade \
        pip==26.1.2 \
        setuptools==83.0.0 \
        wheel==0.46.3 && \
    pip install --no-cache-dir -r requirements.txt && \
    if [ "$INSTALL_AI_DEPS" = "true" ]; then \
        pip install --no-cache-dir -r requirements-ai.txt; \
    fi

COPY . .

RUN groupadd --system openshield && \
    useradd --system --gid openshield --no-create-home openshield && \
    chown -R openshield:openshield /app

USER openshield

ENV PORT=8000

EXPOSE 8000

CMD ["./startup.sh"]
