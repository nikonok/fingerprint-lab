# fingerprint-lab

A TLS endpoint that records what clients reveal before and during their first request, including the raw ClientHello, JA4, the HTTP/2 fingerprint (SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order) and header order. It is used to compare browsers, HTTP libraries and automation tools.

## Layout

| Path | What |
|---|---|
| `cmd/fpserver` | The endpoint. Serves JSON per request and appends one record per connection to `captures/*.jsonl` |
| `cmd/goclient` | Go stdlib client, one of the compared clients |
| `internal/capture` | Terminates TLS itself: records raw client bytes before TLS and decrypted bytes after it |
| `internal/fingerprint` | Parsers: ClientHello, JA4 / JA4_r, HTTP/2, HTTP/1 header order |
| `clients/playwright` | Playwright runner (Node) |
| `scripts/run-clients.sh` | Sends one labelled request per client to a running server |
| `captures/` | Local JSONL output, git-ignored; small curated samples go in `captures/sample/` |

## How it works

`capture.Listener` wraps each accepted TCP connection twice: a recorder under `tls.Server` keeps the raw bytes (ClientHello first), and `capture.Conn` keeps a copy of the first decrypted bytes. `net/http` never sees a `*tls.Conn`. It runs with HTTP/1 and unencrypted HTTP/2 enabled (`http.Protocols`) and picks the protocol from the HTTP/2 preface, which matches the ALPN the TLS layer negotiated. Handlers reach the connection through `capture.FromContext`.

Records store `raw_client_bytes` and `plaintext_prefix`, so captures can be re-parsed after a parser change without re-capturing.

## Commands

```sh
go run ./cmd/fpserver                    # https://127.0.0.1:8443, self-signed cert
./scripts/run-clients.sh                 # curl h1/h2, Go h1/h2, Playwright if installed
go vet ./... && go test ./...
```

Go 1.27 (`go.mod`); with `GOTOOLCHAIN=auto` an older local Go downloads it.

## Conventions

- **Parsers take bytes and return values.** No I/O and no globals in `internal/fingerprint`. Truncated or hostile input returns an error and never panics.
- **Wire order is data.** Keep lists in the order received, GREASE included. Sorting and filtering belong in the function that builds a specific fingerprint.
- **Verify against an independent source.** JA4 output is checked against Wireshark (`tls.handshake.ja4`) or the FoxIO reference implementation on the same capture. HTTP/2 output is checked against Wireshark's HTTP/2 dissector. Test vectors come from real captures, stored under `internal/fingerprint/testdata/`.
- **Log with `log/slog`.** Structured key/value pairs (`slog.Error("write record", "err", err)`). Each `main` sets the default logger and takes a `-log-level` flag (debug|info|warn|error, default info). No `log` or `fmt` printing for diagnostics. Parse failures on attacker-controlled input log at Debug, not Info, so clients can't flood the logs.
- **Claims are measurements.** Any comparison in the README or a write-up names the client versions, the capture it came from, and what was not verified.
- **Don't commit** raw bulk captures, pcaps, keys or certificates. Commit a small sample and the command that produced it.
- Commits follow Conventional Commits (`type(scope): description`, imperative, subject ≤ 50 chars).

## Agent instructions

`AGENTS.md` is the instruction file for every coding agent. `CLAUDE.md` contains only `@AGENTS.md`, so Claude Code imports this file. Edit `AGENTS.md`, never `CLAUDE.md`.
