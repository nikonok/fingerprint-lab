// Package fingerprint turns captured client bytes into fingerprints: the
// parsed ClientHello, JA4, the HTTP/2 (Akamai-style) fingerprint and header
// order.
package fingerprint

import "errors"

// ErrNotImplemented is returned by parsers that are still stubs.
var ErrNotImplemented = errors.New("not implemented")
