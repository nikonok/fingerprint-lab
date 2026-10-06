package fingerprint

import (
	"bufio"
	"bytes"
	"io"
)

// H1Head is the parse result of H1HeaderOrder.
type H1Head struct {
	// Names holds the header field names in wire order with original case;
	// duplicates are kept. Names are the only whitespace-normalised part:
	// padding around the name is trimmed, so "Host : x" records as "Host".
	Names []string `json:"names"`

	// Truncated reports that the input ended before the blank line that
	// terminates the head: the capture limit cut the bytes, or the client
	// never finished sending. The final line is used only when its name is
	// colon-terminated, so a cut mid-name never emits a partial entry.
	Truncated bool `json:"truncated,omitempty"`

	// Malformed reports that a line violated the field syntax of RFC 9112:
	// no colon, an empty field name, or an obs-fold continuation before any
	// field line. Malformed lines are skipped; parsing continues.
	Malformed bool `json:"malformed,omitempty"`
}

// H1HeaderOrder parses the head of an HTTP/1.x request from its raw bytes and
// returns the header field names in the order the client sent them.
//
// net/http parses headers into http.Header, a map with canonicalised keys,
// which loses both order and case; both are client signals, so they come from
// the raw bytes here.
//
// Input is decrypted bytes starting with the request line
// (capture.Conn.PlaintextPrefix). Parsing stops at the blank line that ends
// the head; body bytes after it are ignored. Truncated or hostile input never
// panics: what was seen is returned with Truncated and/or Malformed set, and
// a non-nil error only when the byte reader itself fails.
//
// Each line is classified as it arrived, before any whitespace handling
// (RFC 9112 §2.1 message format, §3 request line, §5 field syntax):
//
//   - The first line is the request line and is skipped.
//   - A line starting with SP or HTAB is obs-fold (RFC 9112 §5.2): a
//     continuation of the previous field's value, never a new field. It is
//     skipped unless no field line was seen yet, which is malformed.
//   - A blank line ends the head.
//   - Otherwise the line is a field line: the name is everything before the
//     first colon. The colon is part of the line's syntax, not of the name,
//     so a value containing colons (including folded ones) never leaks a
//     spurious name.
func H1HeaderOrder(plaintext []byte) (H1Head, error) {
	var head H1Head
	head.Names = []string{}

	reader := bufio.NewReader(bytes.NewReader(plaintext))
	seenRequestLine := false
	seenField := false

	for {
		// Read one full logical line, accumulating fragments so that lines
		// longer than the bufio buffer are not mistaken for truncation.
		var line []byte
		var err error
		for {
			var frag []byte
			frag, err = reader.ReadSlice('\n')
			line = append(line, frag...)
			if err != bufio.ErrBufferFull {
				break
			}
		}
		if err != nil && err != io.EOF {
			return head, err
		}
		truncated := err == io.EOF

		if !seenRequestLine {
			seenRequestLine = true
			if truncated {
				head.Truncated = true
				return head, nil
			}
			continue
		}

		if len(line) == 0 {
			// EOF where the terminating blank line was expected.
			head.Truncated = true
			return head, nil
		}

		// obs-fold: a continuation carries value bytes of the previous
		// field, never a header name.
		if line[0] == ' ' || line[0] == '\t' {
			if !seenField {
				head.Malformed = true
			}
			if truncated {
				head.Truncated = true
				return head, nil
			}
			continue
		}

		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			// Blank line ends the head; only reachable with the LF seen.
			return head, nil
		}

		name, _, found := bytes.Cut(trimmed, []byte(":"))
		name = bytes.TrimSpace(name)
		switch {
		case !found && truncated:
			// Cut mid-line: the fragment carries no colon, so no complete
			// name; report only the truncation.
			head.Truncated = true
			return head, nil
		case !found:
			head.Malformed = true
		case len(name) == 0:
			head.Malformed = true
		default:
			head.Names = append(head.Names, string(name))
			seenField = true
		}
		if truncated {
			head.Truncated = true
			return head, nil
		}
	}
}
