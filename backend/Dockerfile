# ForSight backend: Kali base so all wrapped pentest tools are available from apt
# https://www.kali.org/docs/containers/official-kalilinux-docker-images/
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

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# droopescan not in Kali apt; install via pip for CMS scanner runner
RUN pip install --no-cache-dir droopescan

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
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
