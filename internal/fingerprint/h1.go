package fingerprint

// H1HeaderOrder returns the header names of an HTTP/1.x request head, in
// wire order and with their original case.
//
// NOT IMPLEMENTED YET. Design notes:
//
// Why it exists
//   - net/http parses headers into http.Header, a map with canonicalised
//     keys, which loses both order and case. Both are client signals, so
//     they have to come from the raw bytes.
//
// Input and output
//   - In: decrypted bytes starting with the request line
//     (capture.Conn.PlaintextPrefix).
//   - Out: header names up to the blank line that ends the head.
//
// Source of truth
//   - RFC 9112 §2.1 message format, §3 request line, §5 field syntax
//
// Library options
//   - bufio.Reader.ReadSlice('\n') or bytes.Cut over lines: enough, and it
//     keeps the original bytes
//   - net/textproto.Reader.ReadMIMEHeader: avoid it; it canonicalises and
//     returns a map, which is the problem this function exists to solve
//
// Traps
//   - Lines end in CRLF; tolerate a bare LF and record that it happened.
//   - Obsolete line folding (a line starting with a space or tab) continues
//     the previous field and is not a new header.
//   - The head may be cut off by the capture limit; return what was seen.
func H1HeaderOrder(plaintext []byte) ([]string, error) {
	return nil, ErrNotImplemented
}
