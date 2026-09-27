// Package capture terminates TLS itself so that both sides of the handshake
// stay observable: the raw bytes the client sent before encryption (the
// ClientHello) and the decrypted bytes it sent after (HTTP/2 preface, SETTINGS,
// HEADERS, or an HTTP/1.1 request head).
//
// net/http never sees a *tls.Conn, so it treats every connection as plaintext.
// The server enables HTTP/1 and unencrypted HTTP/2 (prior knowledge), and
// net/http picks the protocol by peeking for the HTTP/2 preface. That matches
// whatever ALPN the TLS layer negotiated.
package capture

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
)

const (
	// maxRaw bounds the pre-TLS capture. A ClientHello fits in one 16 KiB
	// record; the rest of the handshake flight may follow it.
	maxRaw = 32 << 10
	// maxPlain bounds the decrypted capture: preface, SETTINGS, WINDOW_UPDATE,
	// PRIORITY and the first HEADERS block all fit well inside this.
	maxPlain = 16 << 10
)

// recorder keeps the first limit bytes that pass through it.
type recorder struct {
	mu     sync.Mutex
	buf    []byte
	limit  int
	frozen bool
}

func (r *recorder) record(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return
	}
	n := min(len(p), r.limit-len(r.buf))
	r.buf = append(r.buf, p[:n]...)
}

func (r *recorder) freeze() {
	r.mu.Lock()
	r.frozen = true
	r.mu.Unlock()
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf...)
}

// rawConn records what the client writes on the wire, before TLS.
type rawConn struct {
	net.Conn
	rec *recorder
}

func (c *rawConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rec.record(p[:n])
	}
	return n, err
}

// Conn is a server-side TLS connection that keeps a copy of the client's raw
// handshake bytes and of the first decrypted bytes it sent.
type Conn struct {
	*tls.Conn
	raw    *recorder
	plain  *recorder
	logged sync.Once
}

// Read decrypts application data. The first successful read means the
// handshake has completed, so the raw capture is frozen there.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.raw.freeze()
		c.plain.record(p[:n])
	}
	return n, err
}

// RawClientBytes returns the TLS records the client sent up to the end of the
// handshake, starting with the record(s) that carry the ClientHello.
func (c *Conn) RawClientBytes() []byte { return c.raw.bytes() }

// PlaintextPrefix returns the first decrypted bytes the client sent.
func (c *Conn) PlaintextPrefix() []byte { return c.plain.bytes() }

// FirstRequest reports true exactly once per connection, so a connection is
// logged once however many requests it carries.
func (c *Conn) FirstRequest() bool {
	first := false
	c.logged.Do(func() { first = true })
	return first
}

// Listener wraps accepted connections in Conn. The handshake runs lazily on
// the first Read, inside net/http's per-connection goroutine and deadlines.
type Listener struct {
	net.Listener
	cfg *tls.Config
}

func NewListener(inner net.Listener, cfg *tls.Config) *Listener {
	return &Listener{Listener: inner, cfg: cfg}
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	raw := &recorder{limit: maxRaw}
	return &Conn{
		Conn:  tls.Server(&rawConn{Conn: c, rec: raw}, l.cfg),
		raw:   raw,
		plain: &recorder{limit: maxPlain},
	}, nil
}

type ctxKey struct{}

// ConnContext is meant for http.Server.ConnContext: it makes the Conn
// reachable from request handlers.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if cc, ok := c.(*Conn); ok {
		return context.WithValue(ctx, ctxKey{}, cc)
	}
	return ctx
}

// FromContext returns the Conn that carried the request, or nil.
func FromContext(ctx context.Context) *Conn {
	cc, _ := ctx.Value(ctxKey{}).(*Conn)
	return cc
}
