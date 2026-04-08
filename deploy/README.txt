Native install (systemd + nginx) — recommended when Docker networking is problematic
===================================================================================

Beginner nginx walkthrough (copy/paste commands):
  deploy/NGINX_STEP_BY_STEP.txt

Quick HTTPS smoke test (you did not miss a step)
-------------------------------------------------
SSL is NOT provided by uvicorn. Nginx terminates TLS on port 443 and proxies
to the API as plain HTTP on port 8000. If you only run:

  uvicorn app.main:app --host 0.0.0.0 --port 8000

you will only ever get HTTP on :8000 — that is expected.

To verify nginx + TLS + proxy (adjust paths to your clone):

  1) Build the SPA:  cd frontend && npm run build
  2) Generate certs:  ./scripts/gen-self-signed-cert.sh YOUR_LAN_IP
  3) sudo mkdir -p /etc/nginx/certs
     sudo cp deploy/certs/forsight.crt deploy/certs/forsight.key /etc/nginx/certs/
  4) Copy deploy/nginx/forsight-site.conf to /etc/nginx/sites-available/forsight
     Edit the file: set  root  to the absolute path of .../frontend/dist
     sudo ln -sf /etc/nginx/sites-available/forsight /etc/nginx/sites-enabled/
     sudo rm -f /etc/nginx/sites-enabled/default    # if it conflicts on 80/443
     sudo nginx -t && sudo systemctl reload nginx
  5) In backend/ (venv active), bind locally so only nginx hits the API:
     python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 \
       --proxy-headers --forwarded-allow-ips='*' --reload
  6) curl -k https://127.0.0.1/api/health
     (-k is required for self-signed.) Or open https://YOUR_LAN_IP/ in a browser.

502 Bad Gateway from nginx means uvicorn is not running or not on 8000.

The dedicated "forsight" Linux user below is optional — for your own machine,
set User=yourlogin in the systemd unit instead, or skip systemd and use the
terminals above for testing.

Assumptions:
  - Repo deployed at /opt/forsight (adjust paths in unit + nginx if different).
  - Kali or another system with the same pentest tools ForSight expects (nmap, nuclei, etc.).
  - Node 18+ for building the frontend; Python 3.11+ for the backend venv.

1) System user and data directory
   sudo mkdir -p /opt/forsight
   sudo useradd --system --home /opt/forsight --shell /usr/sbin/nologin forsight
   sudo chown forsight:forsight /opt/forsight
   sudo mkdir -p /var/lib/forsight
   sudo chown forsight:forsight /var/lib/forsight
   sudo mkdir -p /etc/forsight
   sudo cp deploy/environment.example /etc/forsight/environment
   sudo chmod 640 /etc/forsight/environment
   sudo chown root:forsight /etc/forsight/environment
   # Edit /etc/forsight/environment — set FORSIGHT_SECRET_KEY at minimum.

2) Backend venv
   cd /opt/forsight/backend
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   .venv/bin/pip install droopescan
   sudo chown -R forsight:forsight /opt/forsight

3) Frontend build
   cd /opt/forsight/frontend
   npm ci
   npm run build
   # Output: frontend/dist (served by nginx)

4) TLS certificates (self-signed)
   sudo mkdir -p /etc/nginx/certs
   ./scripts/gen-self-signed-cert.sh YOUR_SERVER_IP
   sudo cp deploy/certs/forsight.crt deploy/certs/forsight.key /etc/nginx/certs/
   sudo chmod 640 /etc/nginx/certs/forsight.key
   sudo chown root:root /etc/nginx/certs/forsight.crt
   sudo chown root:ssl-cert /etc/nginx/certs/forsight.key   # or root:root if no ssl-cert group

5) Optional: MkDocs /docs
   From repo root: pip install -r docs/requirements.txt && mkdocs build -d /opt/forsight/site
   Uncomment FORSIGHT_DOCS_SITE_DIR in forsight-backend.service or set in /etc/forsight/environment.

6) systemd
   sudo chmod +x /opt/forsight/deploy/forsight-prestart.sh
   sudo cp deploy/systemd/forsight-backend.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now forsight-backend.service
   sudo systemctl status forsight-backend.service

7) nginx (remove or disable default site if it conflicts on 80/443)
   sudo cp deploy/nginx/forsight-site.conf /etc/nginx/sites-available/forsight
   sudo ln -sf /etc/nginx/sites-available/forsight /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx

8) Firewall
   Allow 443 (and 80 if you use the redirect) to the host.

Access: https://YOUR_IP/  (default login forsight / forsight unless you set a password hash).

Docker: docker-compose.yml remains available for container deployments but is not required.
