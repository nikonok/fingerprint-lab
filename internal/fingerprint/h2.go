package fingerprint

import (
	"bytes"
	"errors"
	"strconv"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

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

var ErrNotHTTP2 = errors.New("not HTTP/2: missing connection preface")

// ParseH2 reads the client's side of an HTTP/2 connection from its first
// decrypted bytes (capture.Conn.PlaintextPrefix) and returns what the client
// revealed before and inside its first request.
//
// The input starts with the 24-byte connection preface (RFC 9113 §3.4),
// followed by frames. Parsing is delegated to golang.org/x/net/http2: a
// single Framer drives the frame loop and a single HPACK decoder
// (Framer.ReadMetaHeaders) decodes header blocks, so CONTINUATION frames
// are merged and fields arrive in wire order.
//
// Recorded decisions:
//   - The first stream-0 WINDOW_UPDATE is the fingerprint; later ones are
//     runtime flow-control noise and must not overwrite it.
//   - SETTINGS ACK frames (empty payload acknowledging the server's
//     SETTINGS) carry no client data and are skipped.
//   - Unknown frame types are skipped, not errors.
//   - Only the first HEADERS block is recorded; later requests on the same
//     connection are skipped (the HPACK decoder still sees them, keeping
//     the dynamic table in sync).
//   - The prefix buffer is capped (16 KiB), so the last frame is routinely
//     truncated. Any read error after a valid preface ends the loop and
//     keeps what was seen; it is not a parse failure. The only errors are
//     a missing or wrong preface.
//
// Known gap: a HEADERS frame with the PRIORITY flag set (Firefox signals
// priority there instead of in PRIORITY frames) decodes correctly, but its
// dependency/weight values are not recorded — see h2-worksheet.md §7.1.
//
// Source of truth: RFC 9113 §4.1 (frame header), §6.2 (HEADERS), §6.5
// (SETTINGS), §6.9 (WINDOW_UPDATE), §6.10 (CONTINUATION), §8.3
// (pseudo-headers); RFC 7541 (HPACK); Akamai "Passive Fingerprinting of
// HTTP/2 Clients" (the Akamai string format, built by buildAkamai).
func ParseH2(plaintext []byte) (*H2Fingerprint, error) {
	if len(plaintext) < 24 || string(plaintext[:24]) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		return nil, ErrNotHTTP2
	}

	fr := http2.NewFramer(nil, bytes.NewReader(plaintext[24:]))
	fr.SetMaxReadFrameSize(1<<24 - 1)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	fp := &H2Fingerprint{}

	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			break
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() { // acknowledgment of server SETTINGS, not part of the fingerprint
				continue
			}
			f.ForeachSetting(func(s http2.Setting) error {
				fp.Settings = append(fp.Settings, Setting{ID: uint16(s.ID), Value: s.Val})
				return nil
			})
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 && fp.WindowUpdate == 0 {
				fp.WindowUpdate = f.Increment
			}
		case *http2.PriorityFrame:
			fp.Priorities = append(fp.Priorities, Priority{
				StreamID:  f.StreamID,
				Exclusive: f.Exclusive,
				DependsOn: f.StreamDep,
				Weight:    f.Weight,
			})
		case *http2.MetaHeadersFrame:
			if fp.PseudoHeaderOrder != nil {
				continue // only the first HEADERS block counts
			}
			for _, hf := range f.Fields {
				if len(hf.Name) > 0 && hf.Name[0] == ':' {
					fp.PseudoHeaderOrder = append(fp.PseudoHeaderOrder, hf.Name)
				} else {
					fp.HeaderOrder = append(fp.HeaderOrder, hf.Name)
				}
			}
		default:
			// ignore unknown frame types
		}
	}

	fp.buildAkamai()

	return fp, nil
}

func (fp *H2Fingerprint) buildAkamai() {
	var buf bytes.Buffer

	// SETTINGS
	for i := range fp.Settings {
		s := fp.Settings[i]
		buf.WriteString(strconv.FormatUint(uint64(s.ID), 10))
		buf.WriteByte(':')
		buf.WriteString(strconv.FormatUint(uint64(s.Value), 10))
		if i < len(fp.Settings)-1 {
			buf.WriteByte(';')
		}
	}
	buf.WriteByte('|')

	// WINDOW_UPDATE
	buf.WriteString(strconv.FormatUint(uint64(fp.WindowUpdate), 10))
	buf.WriteByte('|')

	// PRIORITY
	if len(fp.Priorities) == 0 {
		buf.WriteByte('0')
	}
	for i := range fp.Priorities {
		p := fp.Priorities[i]
		buf.WriteString(strconv.FormatUint(uint64(p.StreamID), 10))
		buf.WriteByte(':')
		if p.Exclusive {
			buf.WriteByte('1')
		} else {
			buf.WriteByte('0')
		}
		buf.WriteByte(':')
		buf.WriteString(strconv.FormatUint(uint64(p.DependsOn), 10))
		buf.WriteByte(':')
		buf.WriteString(strconv.FormatUint(uint64(p.Weight), 10))
		if i < len(fp.Priorities)-1 {
			buf.WriteByte(',')
		}
	}
	buf.WriteByte('|')

	// PSEUDO_HEADER_ORDER
	for i := range fp.PseudoHeaderOrder {
		p := fp.PseudoHeaderOrder[i]
		if len(p) < 2 {
			continue // skip malformed pseudo-header names
		}
		buf.WriteByte(p[1]) // letter code: the character after ':'
		if i < len(fp.PseudoHeaderOrder)-1 {
			buf.WriteByte(',')
		}
	}

	fp.Akamai = buf.String()
}
