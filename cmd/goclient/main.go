// Command goclient makes one request with the Go standard library client, so
// its fingerprint can be compared with browsers and curl.
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	url := flag.String("url", "https://localhost:8443/", "endpoint")
	h1 := flag.Bool("h1", false, "force HTTP/1.1")
	var level slog.Level
	flag.TextVar(&level, "log-level", slog.LevelInfo, "log level: debug, info, warn or error")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	tr := &http.Transport{
		// Skipping verification does not change the ClientHello.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// A custom TLSClientConfig silently disables HTTP/2 unless this is set.
		ForceAttemptHTTP2: !*h1,
	}
	if *h1 {
		// A non-nil empty map is the documented way to disable HTTP/2.
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	resp, err := (&http.Client{Transport: tr}).Get(*url)
	if err != nil {
		slog.Error("request", "err", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		slog.Error("read body", "err", err)
		os.Exit(1)
	}
}
