# fingerprint-lab

Captures client signals across the detection stack, from TLS ClientHello (JA4) and the HTTP/2 fingerprint up to the in-page JavaScript surface. It compares real browsers, curl, Go stdlib, uTLS, Playwright and anti-detect browsers.

The goal is an entropy and inconsistency table: which signals discriminate, which are cheap to forge, and where each disguise falls apart.

Work in progress.

## Running

```sh
go run ./cmd/fpserver          # https://127.0.0.1:8443, self-signed certificate
./scripts/run-clients.sh       # curl, Go stdlib, Playwright; prints the Chrome command
```

Each connection is returned as JSON and appended to `captures/captures.jsonl`. A record holds the TLS parameters, the raw client bytes and decrypted prefix, and the fingerprints derived from them.

Status: capture works end to end; the ClientHello, JA4 and HTTP/2 parsers are not implemented yet.
