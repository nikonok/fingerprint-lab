# fingerprint-lab

Captures client signals across the detection stack, from TLS ClientHello (JA4) and the HTTP/2 fingerprint up to the in-page JavaScript surface. It compares real browsers, curl, Go stdlib, uTLS, Playwright and anti-detect browsers.

The goal is an entropy and inconsistency table: which signals discriminate, which are cheap to forge, and where each disguise falls apart.

Work in progress.
