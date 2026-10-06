package fingerprint

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestH1HeaderOrderBasic checks H1HeaderOrder against a hand-built request
// head. The head is deliberately out of alphabetical order, mixes case, and
// includes the anomalies the parser has to get right:
//
//   - duplicate name (X-Dupe, twice, in wire order)
//   - a line folded per obs-fold (the indented continuation of X-Folded)
//   - trailing body bytes after the blank line (the parser must stop there)
//
// The expected list is derived from the raw bytes by reading the fixture top
// to bottom: one entry per field line, name up to the first ':', original
// case, first line skipped, continuation line skipped.
func TestH1HeaderOrderBasic(t *testing.T) {
	head := "POST /a?b=1 HTTP/1.1\r\n" +
		"uSer-AGENT: dummy/1.0\r\n" +
		"Host: fp.test\r\n" +
		"X-Dupe: first\r\n" +
		"Accept: */*\r\n" +
		"X-Folded: one\r\n" +
		" two\r\n" +
		"Content-Length: 5\r\n" +
		"X-Dupe: second\r\n" +
		"\r\n" +
		"HELLO"

	want := []string{
		"uSer-AGENT",
		"Host",
		"X-Dupe",
		"Accept",
		"X-Folded",
		"Content-Length",
		"X-Dupe",
	}

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.False(t, got.Truncated, "expected complete result")
	assert.False(t, got.Malformed, "expected well-formed head")
	assert.Equal(t, want, got.Names, "header order mismatch")
}

// TestH1HeaderOrderFoldWithColon guards the case where an obs-fold
// continuation contains a colon. The continuation is part of the previous
// field's value (RFC 9112 §5.2), so it must not contribute a header name —
// the bytes "two: three" here are value bytes of X-Folded, not a field.
func TestH1HeaderOrderFoldWithColon(t *testing.T) {
	head := "POST /a HTTP/1.1\r\n" +
		"X-Folded: one\r\n" +
		" two: three\r\n" + // obs-fold continuation, space-indented
		"\t four: five\r\n" + // obs-fold continuation, tab-indented
		"Host: fp.test\r\n" +
		"\r\n"

	want := []string{"X-Folded", "Host"}

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.False(t, got.Malformed, "obs-fold is legal, not malformed")
	assert.Equal(t, want, got.Names, "fold continuations must not emit header names")
}

// TestH1HeaderOrderFoldBeforeAnyField covers an indented line where the first
// field line is expected. Obs-fold continues a previous field (RFC 9112 §5.2);
// with no field seen yet the line is malformed, not a skippable fold, and its
// colon must not leak a name.
func TestH1HeaderOrderFoldBeforeAnyField(t *testing.T) {
	head := "POST /a HTTP/1.1\r\n" +
		" Host: x\r\n" +
		"X-Real: y\r\n" +
		"\r\n"

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.True(t, got.Malformed, "fold with no preceding field is malformed")
	assert.Equal(t, []string{"X-Real"}, got.Names, "indented first line must not emit a name")
}

// TestH1HeaderOrderMalformedLines covers field-line violations: a line with
// no colon and a line with an empty name. Both are flagged; the well-formed
// lines around them survive in order.
func TestH1HeaderOrderMalformedLines(t *testing.T) {
	head := "POST /a HTTP/1.1\r\n" +
		"Host: fp.test\r\n" +
		"no-colon-here\r\n" +
		": empty-name\r\n" +
		"X-After: z\r\n" +
		"\r\n"

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.True(t, got.Malformed)
	assert.Equal(t, []string{"Host", "X-After"}, got.Names)
}

// TestH1HeaderOrderNameTrimmed covers whitespace before the colon: the name
// is trimmed for the table, and the head is not flagged — the line is a
// valid field line as far as this parser's contract goes.
func TestH1HeaderOrderNameTrimmed(t *testing.T) {
	head := "POST /a HTTP/1.1\r\n" +
		"Host : fp.test\r\n" +
		"\r\n"

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.False(t, got.Malformed)
	assert.Equal(t, []string{"Host"}, got.Names)
}

// TestH1HeaderOrderTruncatedCleanCut: the head ends after a complete field
// line whose CRLF has not arrived. The name is colon-terminated, so it is
// kept; the head is reported truncated.
func TestH1HeaderOrderTruncatedCleanCut(t *testing.T) {
	head := "POST /a HTTP/1.1\r\n" +
		"Host: fp.test\r\n" +
		"X-Last: 1"

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.True(t, got.Truncated, "head without terminating blank line is truncated")
	assert.False(t, got.Malformed)
	assert.Equal(t, []string{"Host", "X-Last"}, got.Names)
}

// TestH1HeaderOrderTruncatedMidName: the cut lands inside a name. Without a
// terminating colon nothing complete was seen, so no partial name is emitted
// and only truncation is reported.
func TestH1HeaderOrderTruncatedMidName(t *testing.T) {
	head := "POST /a HTTP/1.1\r\n" +
		"Ho"

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.True(t, got.Truncated)
	assert.False(t, got.Malformed, "a cut mid-line is not malformed syntax")
	assert.Empty(t, got.Names)
}

// TestH1HeaderOrderNoEndline: input ending right after a field line's CRLF,
// with the blank line never sent.
func TestH1HeaderOrderNoEndline(t *testing.T) {
	head := "POST /a?b=1 HTTP/1.1\r\n" +
		"uSer-AGENT: dummy/1.0\r\n" +
		"Host: fp.test\r\n"

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.True(t, got.Truncated)
	assert.False(t, got.Malformed)
	assert.Equal(t, []string{"uSer-AGENT", "Host"}, got.Names)
}

// TestH1HeaderOrderLongLine: a field line beyond the bufio buffer must be
// accumulated, not mistaken for truncation or an error.
func TestH1HeaderOrderLongLine(t *testing.T) {
	longName := strings.Repeat("X", 70_000)
	head := "POST /a HTTP/1.1\r\n" + longName + ": v\r\n\r\n"

	got, err := H1HeaderOrder([]byte(head))
	require.NoError(t, err)

	assert.False(t, got.Truncated)
	assert.False(t, got.Malformed)
	require.Len(t, got.Names, 1)
	assert.Equal(t, longName, got.Names[0])
}
