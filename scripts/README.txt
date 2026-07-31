gen-self-signed-cert.sh
  Creates deploy/certs/forsight.crt and forsight.key for nginx (self-signed TLS).
  Re-run with a new IP or DNS name when clients reach the app at a different host.

  ./scripts/gen-self-signed-cert.sh
  ./scripts/gen-self-signed-cert.sh 192.168.1.50

  Optional: OUTDIR=/other/path ./scripts/gen-self-signed-cert.sh 10.0.0.1

  Equivalent wrapper: ./deploy/gen-self-signed-cert.sh (same script)

forsight-tools
  Installs or updates external CLI tools listed in scripts/tools.manifest.json (apt, pip,
  cloud_enum). Use verify to check PATH. See README.md "Quick start (local)".

  ./scripts/forsight-tools install [--user]
  ./scripts/forsight-tools update [all|apt|pip|cloud_enum|nuclei] [--user]
  ./scripts/forsight-tools verify
  ./scripts/forsight-tools list
