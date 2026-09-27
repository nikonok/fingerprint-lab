#!/usr/bin/env bash
# Sends one labelled request from each non-browser client to a running
# fpserver. Chrome is driven by hand; the command is printed at the end.
set -euo pipefail

URL="${1:-https://localhost:8443/}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

run() {
  echo "== $1"
  shift
  "$@" >/dev/null && echo ok || echo "failed ($?)"
}

run curl-h2 curl -sk --http2 "${URL}?label=curl-h2"
run curl-h1 curl -sk --http1.1 "${URL}?label=curl-h1"
run go-h2 go run "$ROOT/cmd/goclient" -url "${URL}?label=go-h2"
run go-h1 go run "$ROOT/cmd/goclient" -h1 -url "${URL}?label=go-h1"

if [ -d "$ROOT/clients/playwright/node_modules" ]; then
  echo "== playwright"
  (cd "$ROOT/clients/playwright" && node fp.mjs "$URL" chromium)
else
  echo "== playwright skipped: cd clients/playwright && npm install && npx playwright install chromium"
fi

cat <<EOF

Chrome (fresh profile, so no extensions or cached state):
  google-chrome --user-data-dir="\$(mktemp -d)" --ignore-certificate-errors "${URL}?label=chrome"
EOF
