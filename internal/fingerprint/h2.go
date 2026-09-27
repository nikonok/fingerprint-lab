package fingerprint

// Setting is one HTTP/2 SETTINGS parameter, in the order the client sent it.
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// Priority is a PRIORITY frame the client sent before its first request.
type Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    uint8  `json:"weight"`
}

// H2Fingerprint is what an HTTP/2 client reveals before and inside its first
// request.
type H2Fingerprint struct {
	Settings          []Setting  `json:"settings"`
	WindowUpdate      uint32     `json:"window_update"` // stream 0 increment, 0 if none
	Priorities        []Priority `json:"priorities,omitempty"`
	PseudoHeaderOrder []string   `json:"pseudo_header_order"` // e.g. [":method", ":authority", ...]
	HeaderOrder       []string   `json:"header_order"`        // regular headers, wire order
	// Akamai is the text form from the Akamai paper:
	// SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
	Akamai string `json:"akamai"`
}

// ParseH2 reads the client's side of an HTTP/2 connection from its first
// decrypted bytes (capture.Conn.PlaintextPrefix).
//
// NOT IMPLEMENTED YET. Design notes:
//
// Input and output
//   - In: bytes that start with the 24-byte connection preface
//     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", followed by frames. The buffer is
//     capped, so the last frame may be truncated.
//   - Out: SETTINGS in wire order, the stream-0 WINDOW_UPDATE, any PRIORITY
//     frames, and the pseudo-header and header order of the first HEADERS
//     block.
//
// Source of truth
//   - RFC 9113: §3.4 preface, §4.1 frame header (length 3, type 1,
//     flags 1, R+stream 4), §6.2 HEADERS (PADDED/PRIORITY flags change the
//     payload layout), §6.5 SETTINGS, §6.9 WINDOW_UPDATE, §6.10
//     CONTINUATION, §8.3 pseudo-headers
//   - RFC 7541 (HPACK): header blocks are compressed and must be decoded
//     to get names in order
//   - Akamai, "Passive Fingerprinting of HTTP/2 Clients" (Black Hat EU
//     2017): the fingerprint format
//
// Library options
//   - golang.org/x/net/http2: NewFramer(nil, reader), then ReadFrame, type
//     switch on *SettingsFrame (ForeachSetting keeps order),
//     *WindowUpdateFrame, *PriorityFrame, *HeadersFrame. Setting
//     Framer.ReadMetaHeaders = hpack.NewDecoder(...) merges CONTINUATION
//     and yields a *MetaHeadersFrame whose Fields keep wire order.
//   - golang.org/x/net/http2/hpack alone: NewDecoder(size, emit). The emit
//     callback fires once per field in order. Use it if frames are split
//     by hand.
//   - Manual frame parsing with encoding/binary: the frame header is 9
//     bytes, so this is easy. HPACK is not; do not hand-roll it.
//   - Wanting x/net means `go get golang.org/x/net`.
//
// Traps
//   - One HPACK decoder per connection. The dynamic table carries over
//     between header blocks, so a fresh decoder per block breaks on the
//     second request.
//   - The PRIORITY flag on HEADERS puts 5 extra bytes before the header
//     block. Some clients signal priority there instead of in PRIORITY
//     frames. Decide whether that belongs in the fingerprint and state the
//     choice.
//   - A server SETTINGS frame never appears here, because this is only
//     what the client sent. The client's SETTINGS ACK does appear.
//   - Frames with an unknown type must be skipped, not treated as errors.
//     Some clients send them on purpose.
//   - A truncated final frame is expected. Stop there without failing the
//     parse.
func ParseH2(plaintext []byte) (*H2Fingerprint, error) {
	return nil, ErrNotImplemented
}
