FROM python:3.11-slim-trixie

WORKDIR /app

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade \
        pip==26.1.2 \
        setuptools==83.0.0 \
        wheel==0.46.3 && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN groupadd --system openshield && \
    useradd --system --gid openshield --no-create-home openshield && \
    chown -R openshield:openshield /app

USER openshield

EXPOSE 8000

CMD ["gunicorn", "--workers", "2", "--threads", "2", "--timeout", "120", "--bind", "0.0.0.0:8000", "api.app:app"]
