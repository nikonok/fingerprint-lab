# HTTP/2 manual verification worksheet

Use this worksheet to verify the real-capture behavior of `ParseH2` before
relying on its output. The exercise is deliberately prediction-first: decode
the capture bytes and write down the expected values before running the
parser. Leave the answer fields blank until you have done that work.

The target is `internal/fingerprint/h2.go`. The existing implementation
records SETTINGS entries in wire order, the first stream-0 WINDOW_UPDATE,
PRIORITY frames, and pseudo-header and regular-header order from the first
request. Its returned value is `*H2Fingerprint`; the Akamai string is built
from SETTINGS, WINDOW_UPDATE, PRIORITY and pseudo-header order. The current
known gap is that priority values carried on a HEADERS frame's PRIORITY flag
are not recorded.

## What counts as finishing this verification

- Hand-decode the curl and Go real captures and record predictions below.
- Compare those predictions with `ParseH2` output.
- Check the available browser capture's SETTINGS order, window increment,
  priority signaling and pseudo-header order against Wireshark.
- Turn the curl hand-decode into an active real-capture regression test.
- Record any mismatch or limitation; do not silently adjust a prediction to
  match the parser.

## Inputs and references

- Captures: `captures/captures.jsonl`; the `plaintext_prefix` value is base64
  encoded decrypted HTTP/2 bytes.
- Parser: `internal/fingerprint/h2.go`.
- Existing real-capture test stub: `internal/fingerprint/h2_test.go`,
  `TestParseH2CurlFixture`.
- Frame and payload rules: RFC 9113 §§3.4, 4.1, 6.2, 6.3, 6.5, 6.9 and 6.10.
- Header decoding and order: RFC 7541 (HPACK), especially §3.
- Akamai serialization context and implementation decisions:
  `h2-worksheet.md`.
- HTTP/2 dissector: Wireshark / `tshark`.

The frame parser in `golang.org/x/net/http2` handles frame boundaries and
HPACK decoding. This exercise checks that the values it produces match the
bytes and the independent dissector; you do not need to implement HPACK.

## Extract the two small fixtures

Run from `fingerprint-lab/`. This writes local binary files from the committed
JSONL captures; it does not change the source capture file.

```sh
python3 - <<'PY'
import base64
import json
from pathlib import Path

targets = {"curl-h2", "go-h2"}
out = Path("/tmp/h2-manual")
out.mkdir(exist_ok=True)
for line in open("captures/captures.jsonl", encoding="utf-8"):
    row = json.loads(line)
    label = row.get("label")
    if label in targets:
        (out / f"{label}.bin").write_bytes(
            base64.b64decode(row["plaintext_prefix"])
        )
        targets.remove(label)
if targets:
    raise SystemExit(f"missing capture(s): {', '.join(sorted(targets))}")
PY
xxd -g 1 /tmp/h2-manual/curl-h2.bin
xxd -g 1 /tmp/h2-manual/go-h2.bin
```

The curl fixture is 125 bytes. The Go fixture is 168 bytes. If those sizes
change, check the capture labels and decoded base64 before proceeding; do not
assume a different prefix has the same frame sequence.

## Decode the wire bytes

The client connection preface is 24 bytes:

```text
PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
```

Check bytes 0–23 character by character. Frames start at offset 24. Each
frame begins with a 9-byte header:

| Header bytes | Meaning | How to decode |
|---|---|---|
| 0–2 | Payload length | Unsigned 24-bit big-endian: `b0<<16 | b1<<8 | b2` |
| 3 | Frame type | `0x04` is SETTINGS; `0x08` is WINDOW_UPDATE |
| 4 | Flags | Interpret according to frame type |
| 5–8 | Reserved bit and stream ID | 31-bit big-endian stream ID; 0 is connection-level |

The next frame begins at `current offset + 9 + payload length`. Do not count
the 9-byte header as part of the payload length.

### SETTINGS frame

A client SETTINGS frame has type `0x04` and stream ID 0. Each setting is six
bytes: a 2-byte big-endian identifier followed by a 4-byte big-endian value.
Decode entries in the order they appear. Preserve unknown IDs and GREASE
IDs; the wire order is part of the fingerprint. Check that the declared
payload length is divisible by six.

Useful standard identifiers are `1` HEADER_TABLE_SIZE, `2` ENABLE_PUSH,
`3` MAX_CONCURRENT_STREAMS, `4` INITIAL_WINDOW_SIZE, `5` MAX_FRAME_SIZE and
`6` MAX_HEADER_LIST_SIZE. A SETTINGS ACK has the ACK flag set and an empty
payload; it is not the client's advertised settings.

### Initial WINDOW_UPDATE

A WINDOW_UPDATE frame has type `0x08` and a four-byte payload. The high bit
is reserved; the remaining 31 bits are the increment. Record the increment
from the first stream-0 WINDOW_UPDATE. Ignore updates on nonzero streams and
do not replace the first connection-level value with later flow-control
traffic.

### Prediction table: fill this before running `ParseH2`

| Capture | Ordered SETTINGS as `id:value` | First stream-0 WINDOW_UPDATE increment | Next relevant frame(s) / notes |
|---|---|---:|---|
| curl-h2 |  |  |  |
| go-h2 |  |  |  |

Before looking at parser output, state exactly which SETTINGS entries and
increment you expect to differ between curl and Go:

```text
Prediction:
```

For each capture, show the byte ranges or offsets used for every decoded
entry and increment. That makes the result reproducible and catches offset
slips.

## Compare with the parser

Only after filling in the prediction table, run the package test suite and
compare with the endpoint output. In one terminal, start the server; in
another, run the existing clients:

```sh
go run ./cmd/fpserver
```

```sh
./scripts/run-clients.sh
go test ./internal/fingerprint
```

The server appends each result to `captures/captures.jsonl`. Use the fresh
`curl-h2` and `go-h2` records for comparison. Compare the parser result to
your written prediction, field by field:

- `Settings`: same identifiers, values and wire order.
- `WindowUpdate`: first stream-0 increment.
- `Priorities`: PRIORITY frames observed before the first request.
- `PseudoHeaderOrder`: decoded pseudo-headers in their original order.
- `HeaderOrder`: decoded regular headers in their original order.
- `Akamai`: serialization of the fields documented in `h2.go`.

Write the comparison here before changing the test stub:

| Capture | Manual prediction agrees? | Parser result / mismatch | Follow-up |
|---|---|---|---|
| curl-h2 |  |  |  |
| go-h2 |  |  |  |

If the parser disagrees with the bytes, first check your offsets and the
frame type/stream ID. Then inspect the `x/net/http2` frame type and accessor
used by `ParseH2`. Keep the original prediction visible and explain any
correction.

## Independent browser check with Wireshark

Use an available browser prefix from `captures/captures.jsonl`. The saved
prefix is decrypted application data, not a packet capture, so Wireshark
cannot open it directly as a pcap. For a fresh run, capture the connection
with TLS session secrets available, then use Wireshark's HTTP/2 dissector (or
`tshark -r <capture.pcapng> -Y http2`). Compare the same browser and request
with the endpoint output.

Check these observable fields:

1. SETTINGS identifiers, values and order.
2. The first stream-0 WINDOW_UPDATE increment.
3. PRIORITY frames and any priority information carried by HEADERS.
4. Pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`, in the
   order actually present), plus regular header order if visible.

Record which browser/capture you checked, and whether the endpoint and
Wireshark agreed. If no fresh pcap or TLS secrets are available, mark this
check pending; do not claim an independent Wireshark verification from the
JSONL prefix alone.

```text
Browser / version:
Capture source:
SETTINGS comparison:
WINDOW_UPDATE comparison:
Priority comparison:
Header-order comparison:
Unverified items:
```

## Activate the curl fixture regression test

Once the manual curl prediction matches `ParseH2`, update
`TestParseH2CurlFixture` in `internal/fingerprint/h2_test.go`:

1. Read the committed curl bytes from `testdata/curl-h2-prefix.bin` (or
   confirm they match the extracted `/tmp` copy).
2. Remove the `t.Skip` line.
3. Replace the empty `wantSettings` and zero placeholder with the values you
   decoded by hand. Keep the SETTINGS in wire order.
4. Run `go test ./internal/fingerprint` and confirm the real-capture test
   passes along with the synthetic tests.
5. If the fixture needs refreshing, regenerate it from `captures.jsonl` and
   review the binary diff before keeping it.

Do not fill expected values by printing `ParseH2` and copying its output:
that would test the parser against itself, not against an independent
prediction.

## Completion record

```text
Curl hand-decode complete:
Go hand-decode complete:
Prediction compared with parser:
Curl regression test active and passing:
Browser checked against Wireshark:
Known mismatch or unverified item:
```

The transport-layer comparison is manually verified only to the extent
recorded above. A passing parser test does not establish that these signals
identify a browser generally or that the capture represents all versions.
