// Command fpserver is a TLS endpoint that records, for every client that
// connects, the raw ClientHello, JA4, the HTTP/2 fingerprint and header order.
// It returns the record as JSON and appends it to a JSONL file.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nikonok/fingerprint-lab/internal/capture"
	"github.com/nikonok/fingerprint-lab/internal/fingerprint"
)

// Record is one connection's capture. Raw bytes are kept so that captures can
// be re-parsed when the parsers change.
type Record struct {
	Time      time.Time `json:"time"`
	Label     string    `json:"label,omitempty"` // ?label=... set by the client runner
	Remote    string    `json:"remote"`
	Proto     string    `json:"proto"`
	UserAgent string    `json:"user_agent"`

	TLSVersion string `json:"tls_version"`
	Cipher     string `json:"cipher"`
	ALPN       string `json:"alpn"`
	SNI        string `json:"sni"`

	ClientHello   *fingerprint.ClientHello   `json:"client_hello,omitempty"`
	JA4           string                     `json:"ja4,omitempty"`
	JA4Raw        string                     `json:"ja4_r,omitempty"`
	H2            *fingerprint.H2Fingerprint `json:"h2,omitempty"`
	H1HeaderOrder []string                   `json:"h1_header_order,omitempty"`

	RawClientBytes  []byte   `json:"raw_client_bytes"` // base64 in JSON
	PlaintextPrefix []byte   `json:"plaintext_prefix"` // base64 in JSON
	Errors          []string `json:"errors,omitempty"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	out := flag.String("out", "captures/captures.jsonl", "JSONL file to append records to")
	certFile := flag.String("cert", "", "certificate PEM (default: generated self-signed)")
	keyFile := flag.String("key", "", "key PEM")
	flag.Parse()

	cert, err := loadCert(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	sink, err := openSink(*out)
	if err != nil {
		log.Fatalf("output: %v", err)
	}
	defer sink.close()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// capture.Listener hands net/http decrypted connections. HTTP/2 on them
	// is "unencrypted" as far as net/http knows, and it is selected by the
	// preface, which matches the ALPN the TLS layer negotiated.
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:           handler(sink),
		ConnContext:       capture.ConnContext,
		Protocols:         &protos,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on https://%s, writing %s", ln.Addr(), *out)
	log.Fatal(srv.Serve(capture.NewListener(ln, tlsCfg)))
}

func handler(sink *sink) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cc := capture.FromContext(r.Context())
		if cc == nil {
			http.Error(w, "no capture for this connection", http.StatusInternalServerError)
			return
		}
		rec := buildRecord(r, cc)
		if cc.FirstRequest() {
			if err := sink.write(rec); err != nil {
				log.Printf("write record: %v", err)
			}
			log.Printf("%-12s %-8s ja4=%s errors=%d", rec.Label, rec.Proto, rec.JA4, len(rec.Errors))
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rec)
	})
}

func buildRecord(r *http.Request, cc *capture.Conn) *Record {
	st := cc.ConnectionState()
	rec := &Record{
		Time:            time.Now().UTC(),
		Label:           r.URL.Query().Get("label"),
		Remote:          r.RemoteAddr,
		Proto:           r.Proto,
		UserAgent:       r.UserAgent(),
		TLSVersion:      tls.VersionName(st.Version),
		Cipher:          tls.CipherSuiteName(st.CipherSuite),
		ALPN:            st.NegotiatedProtocol,
		SNI:             st.ServerName,
		RawClientBytes:  cc.RawClientBytes(),
		PlaintextPrefix: cc.PlaintextPrefix(),
	}
	fail := func(what string, err error) {
		rec.Errors = append(rec.Errors, what+": "+err.Error())
	}

	ch, err := fingerprint.ParseClientHello(rec.RawClientBytes)
	if err != nil {
		fail("client_hello", err)
	} else {
		rec.ClientHello = ch
		if rec.JA4, err = fingerprint.JA4(ch, false); err != nil {
			fail("ja4", err)
		}
		if rec.JA4Raw, err = fingerprint.JA4Raw(ch, false); err != nil {
			fail("ja4_r", err)
		}
	}

	if r.ProtoMajor == 2 {
		if rec.H2, err = fingerprint.ParseH2(rec.PlaintextPrefix); err != nil {
			fail("h2", err)
		}
	} else {
		if rec.H1HeaderOrder, err = fingerprint.H1HeaderOrder(rec.PlaintextPrefix); err != nil {
			fail("h1_header_order", err)
		}
	}
	return rec
}

func loadCert(certFile, keyFile string) (tls.Certificate, error) {
	if certFile == "" {
		return capture.SelfSigned()
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

type sink struct {
	mu sync.Mutex
	f  *os.File
}

func openSink(path string) (*sink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &sink{f: f}, nil
}

func (s *sink) write(rec *Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.f.Write(append(b, '\n'))
	return err
}

func (s *sink) close() { s.f.Close() }
