Place TLS files here before starting Docker (or nginx will fail to bind 443):

  forsight.crt
  forsight.key

Generate them from the repo root:

  chmod +x scripts/gen-self-signed-cert.sh
  ./scripts/gen-self-signed-cert.sh YOUR_SERVER_IP

Include the IP or hostname clients use in the browser so the certificate SAN matches
(otherwise you will still get browser warnings).

For a public IP or custom hostname, either re-run the script with that IP or set
FORSIGHT_CORS_ORIGINS=https://your-host:443 in docker-compose / environment.
