package fingerprint

// JA4 computes the JA4 TLS client fingerprint, e.g.
// t13d1516h2_8daaf6152771_e5627efa2ab1.
//
// NOT IMPLEMENTED YET. Design notes:
//
// Input and output
//   - In: a parsed ClientHello; quic selects the transport character
//     ('t' for TCP, 'q' for QUIC).
//   - Out: JA4 in its hashed form, a_b_c.
//
// Source of truth
//   - FoxIO-LLC/ja4: technical_details/JA4.md is the spec. python/ja4.py
//     and rust/ja4/src/tls.rs are the reference implementations, and their
//     pcaps and expected outputs make ready-made test vectors.
//   - Wireshark 4.2+ computes JA4 itself (field tls.handshake.ja4). Compare
//     against it on the same capture.
//
// Structure
//   - a: transport, TLS version, SNI marker (d/i), cipher count, extension
//     count, ALPN marker. It is human-readable.
//   - b: truncated SHA-256 over the sorted cipher list.
//   - c: truncated SHA-256 over the sorted extension list, followed by the
//     signature algorithms in wire order.
//
// Library options
//   - crypto/sha256, encoding/hex: hashing, then truncation to 12 hex chars
//   - slices.Sort: sorting uint16 values
//   - fmt / strings.Builder: 4-digit lowercase hex fields, comma-joined
//
// Traps (check each one against JA4.md, not memory)
//   - GREASE (RFC 8701): values of the form 0x?a?a with equal bytes. They
//     must be excluded from counts, lists and the version choice.
//   - The version comes from the highest supported_versions entry when that
//     extension is present, not from legacy_version.
//   - The extension count in `a` includes SNI and ALPN, but the list hashed
//     in `c` excludes them.
//   - Counts are two digits and capped at 99.
//   - ALPN marker: first and last character of the first ALPN value, with a
//     special rule for non-alphanumeric values; "00" when ALPN is absent.
//   - Empty lists hash to "000000000000", not to the SHA-256 of "".
//   - Sorting is what makes JA4 stable under Chrome's extension-order
//     shuffling. A test that captures the same browser twice must produce
//     the same JA4.
func JA4(ch *ClientHello, quic bool) (string, error) {
	return "", ErrNotImplemented
}

// JA4Raw returns the unhashed form (JA4_r) with the sorted lists in clear
// text. It is used for diffing two clients field by field.
//
// NOT IMPLEMENTED YET. It shares every rule with JA4 except the final
// hashing step, so build both on one helper.
func JA4Raw(ch *ClientHello, quic bool) (string, error) {
	return "", ErrNotImplemented
}
