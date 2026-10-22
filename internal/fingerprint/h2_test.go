package fingerprint

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var testH2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// clientBurst assembles a client-side prefix: preface plus whatever frames
// the caller writes through an x/net Framer. Synthetic fixtures only — real
// captures live in testdata/ and come from captures.jsonl.
func clientBurst(t *testing.T, write func(t *testing.T, fr *http2.Framer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(testH2Preface)
	fr := http2.NewFramer(&buf, nil)
	write(t, fr)
	return buf.Bytes()
}

func TestParseH2RejectsH1(t *testing.T) {
	h1 := []byte("GET / HTTP/1.1\r\nHost: fp.test\r\n\r\n")
	fp, err := ParseH2(h1)
	assert.Error(t, err, "an H1 request line is not an H2 preface")
	assert.Nil(t, fp)
}

func TestParseH2ShortInput(t *testing.T) {
	for _, n := range []int{0, 5, 23} {
		fp, err := ParseH2(testH2Preface[:n])
		assert.Error(t, err, "prefix shorter than 24 bytes must fail at length %d", n)
		assert.Nil(t, fp)
	}
}

func TestParseH2SettingsAndWindowUpdate(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
			http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		))
		require.NoError(t, fr.WriteWindowUpdate(0, 33333))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)

	// Wire order, unsorted — order is the signal.
	want := []Setting{
		{ID: 1, Value: 4096},
		{ID: 3, Value: 100},
	}
	assert.Equal(t, want, fp.Settings)
	assert.Equal(t, uint32(33333), fp.WindowUpdate)

	// Akamai string pinned: numeric ids, ';' between settings, ',' in the
	// pseudo-order section, empty sections stay empty (no HEADERS here).
	assert.Equal(t, "1:4096;3:100|33333|0|", fp.Akamai)
}

func TestParseH2HeaderOrder(t *testing.T) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "fp.test"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
		{Name: "user-agent", Value: "dummy/1.0"},
	} {
		require.NoError(t, enc.WriteField(f))
	}

	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: block.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		}))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{":method", ":authority", ":scheme", ":path"}, fp.PseudoHeaderOrder)
	assert.Equal(t, []string{"user-agent"}, fp.HeaderOrder)
	assert.Equal(t, "|0|0|m,a,s,p", fp.Akamai)
}

// TestParseH2SettingsAckSkipped: the client ACKs the server's SETTINGS
// (empty payload, ACK flag) somewhere in the prefix — it is not data and
// must not pollute the fingerprint.
func TestParseH2SettingsAckSkipped(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		))
		require.NoError(t, fr.WriteSettingsAck())
		require.NoError(t, fr.WriteWindowUpdate(0, 999))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []Setting{{ID: 1, Value: 4096}}, fp.Settings)
	assert.Equal(t, uint32(999), fp.WindowUpdate)
}

// TestParseH2UnknownFrameSkipped: unknown frame types must be skipped by
// their declared length, not treated as errors — some clients send them on
// purpose.
func TestParseH2UnknownFrameSkipped(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		))
		require.NoError(t, fr.WriteRawFrame(0x1f, 0, 0, []byte{1, 2, 3}))
		require.NoError(t, fr.WriteWindowUpdate(0, 999))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []Setting{{ID: 1, Value: 4096}}, fp.Settings)
	assert.Equal(t, uint32(999), fp.WindowUpdate)
}

// TestParseH2PriorityFrames: PRIORITY frames recorded in wire order, raw
// weight byte kept, and the Akamai priority section is
// "stream:exclusive:dependency:weight" joined with ','.
func TestParseH2PriorityFrames(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WritePriority(3, http2.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 200}))
		require.NoError(t, fr.WritePriority(5, http2.PriorityParam{StreamDep: 3, Exclusive: true, Weight: 100}))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []Priority{
		{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 200},
		{StreamID: 5, Exclusive: true, DependsOn: 3, Weight: 100},
	}, fp.Priorities)
	assert.Equal(t, "|0|3:0:0:200,5:1:3:100|", fp.Akamai)
}

// TestParseH2WindowUpdateFirstWins pins the §7.4 decision: the *initial*
// stream-0 increment is the fingerprint; a later one must not overwrite it.
func TestParseH2WindowUpdateFirstWins(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteWindowUpdate(0, 111))
		require.NoError(t, fr.WriteWindowUpdate(0, 222))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(111), fp.WindowUpdate)
}

// TestParseH2StreamWindowUpdateIgnored: per-stream WINDOW_UPDATEs are
// request tuning, not the connection-level signal.
func TestParseH2StreamWindowUpdateIgnored(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteWindowUpdate(1, 1000))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), fp.WindowUpdate)
}

// TestParseH2GreaseSettingsKept: GREASE-like settings ids stay in the data,
// in wire order — filtering belongs to the fingerprint builder, not the
// parser.
func TestParseH2GreaseSettingsKept(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings(
			http2.Setting{ID: 0x2a2a, Val: 1},
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []Setting{{ID: 0x2a2a, Value: 1}, {ID: 1, Value: 4096}}, fp.Settings)
}

// TestParseH2SecondHeadersIgnored: only the first request's header order is
// the fingerprint; a second HEADERS block on the same connection must not
// overwrite it.
func TestParseH2SecondHeadersIgnored(t *testing.T) {
	var first, second bytes.Buffer
	enc1 := hpack.NewEncoder(&first)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
	} {
		require.NoError(t, enc1.WriteField(f))
	}
	enc2 := hpack.NewEncoder(&second)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":authority", Value: "fp.test"},
	} {
		require.NoError(t, enc2.WriteField(f))
	}

	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: first.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		}))
		require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      3,
			BlockFragment: second.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		}))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{":method", ":path"}, fp.PseudoHeaderOrder)
}

// TestParseH2TruncatedFinalFrame pins the §7.3 decision: a prefix cap cut
// mid-frame after a valid preface is not an error — keep what was seen.
// Flip this test if you decide otherwise.
func TestParseH2TruncatedFinalFrame(t *testing.T) {
	full := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		))
	})
	// Cut inside the SETTINGS payload (frame header complete, payload not).
	raw := full[:24+9+2]

	fp, err := ParseH2(raw)
	require.NoError(t, err, "truncation after a valid preface keeps the parse")
	assert.Empty(t, fp.Settings)
}

// TestParseH2PrefaceOnly: a valid preface with zero frames is a legitimate
// prefix (the capture cap may sit exactly at the preface) — success, with
// everything empty and the connection window increment zero.
func TestParseH2PrefaceOnly(t *testing.T) {
	fp, err := ParseH2(testH2Preface)
	require.NoError(t, err)
	assert.Empty(t, fp.Settings)
	assert.Empty(t, fp.Priorities)
	assert.Empty(t, fp.PseudoHeaderOrder)
	assert.Empty(t, fp.HeaderOrder)
	assert.Equal(t, uint32(0), fp.WindowUpdate)
	assert.Equal(t, "|0|0|", fp.Akamai)
}

// TestParseH2EmptySettingsFrame: an empty SETTINGS frame (length 0, no ACK
// flag) is what several real clients open with — it must parse successfully
// and produce an empty, non-nil-equivalent settings list. The ACK-skip test
// pins the flag distinction; this pins the empty-payload case.
func TestParseH2EmptySettingsFrame(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings())
		require.NoError(t, fr.WriteWindowUpdate(0, 15663105))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Empty(t, fp.Settings)
	assert.Equal(t, uint32(15663105), fp.WindowUpdate)
}

// TestParseH2ContinuationMerges: a header block split across HEADERS +
// CONTINUATION must decode as one block — pseudo-header order comes out
// complete, and the split point (mid-HPACK) must not corrupt names.
func TestParseH2ContinuationMerges(t *testing.T) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "fp.test"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
		{Name: "accept", Value: "*/*"},
		{Name: "user-agent", Value: "dummy/1.0"},
	} {
		require.NoError(t, enc.WriteField(f))
	}
	frag := block.Bytes()
	cut := len(frag) / 2

	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: frag[:cut],
			EndHeaders:    false,
			EndStream:     true,
		}))
		require.NoError(t, fr.WriteContinuation(1, true, frag[cut:]))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{":method", ":authority", ":scheme", ":path"}, fp.PseudoHeaderOrder)
	assert.Equal(t, []string{"accept", "user-agent"}, fp.HeaderOrder)
}

// TestParseH2HeadersWithPriorityFlag: the PRIORITY flag on HEADERS puts five
// extra bytes before the header block; the block must still decode to the
// right order. Whether the priority values themselves belong in the
// fingerprint is an open design question — this test only pins that their
// presence never corrupts header order.
func TestParseH2HeadersWithPriorityFlag(t *testing.T) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
		{Name: "user-agent", Value: "dummy/1.0"},
	} {
		require.NoError(t, enc.WriteField(f))
	}

	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: block.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
			Priority:      http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255},
		}))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{":method", ":path"}, fp.PseudoHeaderOrder)
	assert.Equal(t, []string{"user-agent"}, fp.HeaderOrder)
}

// TestParseH2InterleavedControlFramesIgnored: DATA, PING and RST_STREAM are
// normal connection traffic, not fingerprint material — they pass through
// without error and without polluting any field.
func TestParseH2InterleavedControlFramesIgnored(t *testing.T) {
	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		))
		require.NoError(t, fr.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
		require.NoError(t, fr.WriteData(1, false, []byte("body")))
		require.NoError(t, fr.WriteRSTStream(1, http2.ErrCodeCancel))
		require.NoError(t, fr.WriteWindowUpdate(0, 777))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []Setting{{ID: 1, Value: 4096}}, fp.Settings)
	assert.Equal(t, uint32(777), fp.WindowUpdate)
	assert.Empty(t, fp.Priorities)
	assert.Empty(t, fp.PseudoHeaderOrder)
	assert.Empty(t, fp.HeaderOrder)
}

// TestParseH2HeaderDuplicatesWireOrder: repeated and non-alphabetical header
// names keep wire order exactly — order is the signal, no sorting or
// deduping at parse time.
func TestParseH2HeaderDuplicatesWireOrder(t *testing.T) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
		{Name: "cookie", Value: "a=1"},
		{Name: "accept-encoding", Value: "gzip"},
		{Name: "cookie", Value: "b=2"},
		{Name: "accept", Value: "*/*"},
	} {
		require.NoError(t, enc.WriteField(f))
	}

	raw := clientBurst(t, func(t *testing.T, fr *http2.Framer) {
		require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: block.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		}))
	})

	fp, err := ParseH2(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{":method", ":path"}, fp.PseudoHeaderOrder)
	assert.Equal(t, []string{"cookie", "accept-encoding", "cookie", "accept"}, fp.HeaderOrder)
}

// TestParseH2NoPanicOnHostileTail: bytes after a valid preface are
// attacker-controlled. Any tail — truncated headers, absurd frame lengths,
// zero-length frames — must never panic, and the err/fp invariant must
// hold: an error means no fingerprint.
func TestParseH2NoPanicOnHostileTail(t *testing.T) {
	tails := map[string][]byte{
		"empty tail":           {},
		"lone zero byte":       {0},
		"partial frame header": {0, 0, 4, 4},
		"declared length max":  {0xff, 0xff, 0xff, 0x4},
		"zero-length unknown":  {0, 0, 0, 0x1f, 0, 0, 0, 0, 0},
		"length but no body":   {0, 0, 100, 0x4, 0, 0, 0, 0, 0},
		"all 0xff":             bytes.Repeat([]byte{0xff}, 64),
	}

	for name, tail := range tails {
		t.Run(name, func(t *testing.T) {
			raw := append(append([]byte{}, testH2Preface...), tail...)
			assert.NotPanics(t, func() {
				fp, err := ParseH2(raw)
				if err != nil {
					assert.Nil(t, fp)
				}
			})
		})
	}
}

// TestParseH2CurlFixture is the real capture: 125 bytes from
// captures/captures.jsonl (curl-h2, curl 7.81.0). Fill in wantSettings and
// wantWindowUpdate from your §9 hand decode BEFORE running ParseH2 — the
// same predict-then-check discipline as JA4 vs Wireshark.
func TestParseH2CurlFixture(t *testing.T) {
	t.Skip("fill expected values from the h2-worksheet §9 hand decode first")

	raw, err := os.ReadFile("testdata/curl-h2-prefix.bin")
	require.NoError(t, err)
	require.Equal(t, 125, len(raw), "fixture drifted — re-extract from captures.jsonl")

	fp, err := ParseH2(raw)
	require.NoError(t, err)

	wantSettings := []Setting{
		// TODO: hand-decode bytes 33..68 of the fixture.
	}
	wantWindowUpdate := uint32(0) // TODO: decode the stream-0 increment.

	assert.Equal(t, wantSettings, fp.Settings)
	assert.Equal(t, wantWindowUpdate, fp.WindowUpdate)
}
