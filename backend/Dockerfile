# ForSight backend: Debian base + pentest tools + Python app
# (Debian mirrors are more reliable in Docker builds than Kali's; for full Kali tool set
# use Kali image when your build environment can reach http.kali.org.)
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install pentest tools available in Debian repos (avoids Kali mirror DNS issues in Docker build)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    dirb \
    whois \
    curl \
    sslscan \
    masscan \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Default wordlists (copied into volume on first run by entrypoint)
COPY data/wordlists/ /app/wordlists-default/

# App
COPY app/ ./app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Data dir: use volume at runtime; entrypoint seeds wordlists if empty
ENV FORSIGHT_DATA_DIR=/app/data
EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
