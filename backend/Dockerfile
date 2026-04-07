# ForSight backend: Kali base so all wrapped pentest tools are available from apt
# https://www.kali.org/docs/containers/official-kalilinux-docker-images/
# Build context: repo root (.) so we can copy docs/ for the /docs endpoint
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install Python and pentest tools used by ForSight runners (recon, nmap, web, enum, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 python3-pip python3-venv \
    nmap nikto dirb whois curl sslscan masscan \
    dnsrecon amass theharvester subfinder \
    nuclei gowitness wpscan \
    snmp samba-common-bin ldap-utils \
    enum4linux-ng \
    testssl.sh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Use a venv so we don't conflict with Kali's system Python packages (e.g. bcrypt)
RUN python3 -m venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# droopescan not in Kali apt; install via pip for CMS scanner runner
RUN pip install --no-cache-dir droopescan

# Build MkDocs site for /docs endpoint (served by FastAPI at port 8000)
COPY docs/ ./docs/
COPY mkdocs.yml .
COPY docs/requirements.txt ./docs-requirements.txt
# So built assets load from /docs/ when served at that path
RUN echo "site_url: http://localhost/docs/" >> mkdocs.yml \
    && pip install --no-cache-dir -r docs-requirements.txt \
    && mkdocs build \
    && rm -rf docs docs-requirements.txt mkdocs.yml

# Default wordlists (copied into volume on first run by entrypoint)
COPY backend/data/wordlists/ /app/wordlists-default/

# App
COPY backend/app/ ./app/
COPY backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Data dir: use volume at runtime; entrypoint seeds wordlists if empty
ENV FORSIGHT_DATA_DIR=/app/data
EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
# Trust X-Forwarded-Proto / Host from nginx so sessions and redirects see HTTPS.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
