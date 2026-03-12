FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    openssl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

ENTRYPOINT ["archiviomd-verify"]
