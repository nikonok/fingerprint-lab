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

## Status

Working: TLS capture end to end; ClientHello parser (tested, fuzzed); JA4 / JA4_r; H1 header order; HTTP/2 fingerprint parsing (SETTINGS order and values, first connection-level WINDOW_UPDATE, PRIORITY frames, and first-request header order). Current curl and Go captures match independent wire-byte predictions; the curl real-capture test and `internal/fingerprint` package tests pass.

## Known gaps

- Multi-record ClientHellos are not re-parsed; the record version is captured but not yet measured as a signal.
- The fingerprint is client-side only: the server's own SETTINGS and frames are absent from the input by construction (same as Akamai's method).
- HTTP/2 over prior-knowledge h2c or Upgrade is out of scope; the endpoint is TLS + ALPN.
- The decrypted-prefix cap is 16 KiB; a client sending more than that in its first header block shows an incomplete header order.
- The Akamai H2 string is pinned to curl-impersonate's published fingerprints, not to a formal spec.
- PRIORITY information carried in a HEADERS frame's priority field is not recorded yet.
- A sample from one HeadlessChrome 156 session is independently dissected by `tshark` with `./scripts/dissect-h2-prefix.sh captures/sample/chrome-headless-156-h2-prefix.bin`. The script wraps the already-decrypted H2 bytes in synthetic TCP headers; SETTINGS, WINDOW_UPDATE and header order match the endpoint parser. This checks H2 dissection, not TLS or real packet-level behavior.
