# Four-client run: JA4 results (2026-10-06)

First end-to-end comparison of real clients against the endpoint. Method:
`fpserver` on `https://127.0.0.1:8443`; `./scripts/run-clients.sh` for curl /
Go stdlib / Playwright; Chrome by hand with a fresh profile. One run, one
machine. Full records (raw ClientHello bytes included) live in
`captures/captures.jsonl` (git-ignored), 7 records.

## Clients

| Client | Version |
|---|---|
| Chrome | 154.0.0.0 (google-chrome-stable, Linux x86_64) |
| curl | 7.81.0 (OpenSSL 3.0.2, nghttp2 1.43.0) |
| Go stdlib | go1.27.1 |
| Playwright | 1.63.0, chromium build 1243 |

## Results

| label | proto | ALPN | TLS / cipher | JA4 | H1 header order |
|---|---|---|---|---|---|
| curl-h2 | HTTP/2.0 | h2 | TLS 1.3 / TLS_AES_128_GCM_SHA256 | `t13d3113h2_e8f1e7e78f70_ce5650b735ce` | — |
| curl-h1 | HTTP/1.1 | http/1.1 | TLS 1.3 / TLS_AES_128_GCM_SHA256 | `t13d3113h1_e8f1e7e78f70_ce5650b735ce` | Host, User-Agent, Accept |
| go-h2 | HTTP/2.0 | h2 | TLS 1.3 / TLS_AES_128_GCM_SHA256 | `t13d1312h2_f57a46bbacb6_f50d94e863eb` | — |
| go-h1 | HTTP/1.1 | _(none)_ | TLS 1.3 / TLS_AES_128_GCM_SHA256 | `t13d131200_f57a46bbacb6_f50d94e863eb` | Host, User-Agent, Accept-Encoding |
| playwright-chromium-headless | HTTP/2.0 | h2 | TLS 1.3 / TLS_AES_128_GCM_SHA256 | `t13d1516h2_8daaf6152771_806a8c22fdea` | — |
| playwright-chromium-headed | HTTP/2.0 | h2 | TLS 1.3 / TLS_AES_128_GCM_SHA256 | `t13d1517h2_8daaf6152771_cb7bf5808d99` | — |
| chrome | HTTP/2.0 | h2 | TLS 1.3 / TLS_AES_128_GCM_SHA256 | `t13d1517h2_8daaf6152771_cb7bf5808d99` | — |

All records: SNI = `localhost`, no parse errors. Every HTTP/2 record carries
the expected `h2: not implemented` (see Known gaps).

## What the results say

1. **curl h1 vs h2 is one byte of JA4.** Identical cipher hash and extension
   hash; only the ALPN marker differs (`h1` vs `h2`) because curl changes
   only the ALPN list in the ClientHello. The ALPN extension is excluded
   from JA4_c's hash input by spec (like SNI), so nothing curl changed
   reaches the hashes.
2. **go-h1 offers no ALPN** (empty ALPN, JA4 a-field `00`): Go's
   `crypto/tls` sends the ALPN extension only when `tls.Config.NextProtos`
   is non-empty, and the h1 run leaves it empty. No browser does this — a
   browser-claimed UA with `00` in its JA4 is a free inconsistency signal.
3. **Go and curl share nothing at the TLS layer**: 13 vs 31 cipher suites,
   so both the a-field counts (`d13` vs `d31`) and the cipher/extension
   hashes differ. TLS 1.3 and `TLS_AES_128_GCM_SHA256` are identical
   everywhere because they are the default first choice of every modern
   stack — a detector gets zero information from them.
4. **Headed Playwright is Chrome, byte for byte.** `playwright-chromium-headed`
   and hand-driven Chrome share JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`.
   Driving a real browser buys nothing at this layer; the automation tells
   for a real-Chromium driver live at H2 frames, header order and JS.
5. **Headless is detectable at the TLS layer.** `playwright-chromium-headless`
   launches the separate headless-shell build, whose ClientHello drops
   extension 0xCA34 (51764) — **Trust Anchor IDs**
   (draft-ietf-tls-trust-anchor-ids), sent by Chrome by default since
   Chrome 141 to advertise which CA trust stores it recognises. The feature
   is not enabled in the stripped headless-shell build, which lacks the
   trust-store component that populates the extension. Effect: same cipher
   hash, extension count 16 vs 17, different extension hash
   (`806a8c22fdea` vs `cb7bf5808d99`). Consequences beyond headless:
   Chromium forks that disable the extension (Edge 153, Brave 154 per
   community captures) diverge from Chrome here, and uTLS's
   `HelloChrome_Auto` profile does not send it
   (refraction-networking/utls#397).
6. **JA4 hides GREASE but counts honestly.** Chrome listed 19 extensions on
   the wire; the a-field says 17. The two GREASE entries are dropped from
   both count and hashes. GREASE values and positions varied per connection
   (0xAAAA, 0x1A1A, 0x6A6A, 0x7A7A, 0x4A4A observed); same-build clients
   still hash equal because JA4 strips GREASE and sorts before hashing. Note
   the count includes SNI and ALPN even though the hash excludes them.
7. **JA4 fingerprints context, not just the client.** The same Chrome build
   against `https://127.0.0.1:8443` produced
   `t13i1516h2_8daaf6152771_cb7bf5808d99`. Chrome never sends SNI for IP
   literals (RFC 6066 §3 requires a DNS name), so the SNI flag flips `d`→`i`
   and the extension count drops by exactly the vanished `server_name`
   extension (17→16); the hashes are unchanged because SNI is excluded from
   JA4_c's input. Detection angle: a domain-fronted request whose JA4
   carries the `i` marker means the client chose not to send SNI — a cheap
   signal worth flagging.

## Independent verification

tls.peet.ws, a separate JA4 implementation, reports
`t13d1517h2_8daaf6152771_cb7bf5808d99` for this Chrome build reached by
domain — an exact match with the endpoint's record. The by-IP variant
(`t13i1516h2_...`, same hashes) is the expected context difference from
observation 7, not a disagreement.

## Known gaps

- **H2 fingerprint** (SETTINGS order, initial WINDOW_UPDATE, pseudo-header
  order): `ParseH2` is still a stub, so the table has no H2 column and every
  HTTP/2 record carries `h2: not implemented` in `errors`.
- **H1 header order** is measured only where HTTP/1.1 was used (curl-h1,
  go-h1); the h2 clients sent no H1 request.
- One run, one machine. GREASE and extension order will vary between runs;
  the JA4s should not.
- The `openssl-min.bin` fixture matches Wireshark 4.6.6, but no capture from
  this run has been re-checked in tshark.

Extension identification per [ScrapFly's TLS extension
database](https://scrapfly.io/web-scraping-tools/ja3-fingerprint/extension/trust-anchors)
and [utls issue #397](https://github.com/refraction-networking/utls/issues/397).
