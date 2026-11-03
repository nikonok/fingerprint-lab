#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -f "$1" ]]; then
	echo "usage: $0 <decrypted-h2-prefix.bin>" >&2
	exit 2
fi

command -v xxd >/dev/null
command -v text2pcap >/dev/null
command -v tshark >/dev/null

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

xxd -g 1 -c 16 "$1" >"$work_dir/prefix.hex"
text2pcap -F pcapng -4 127.0.0.1,127.0.0.1 -T 41584,443 \
	"$work_dir/prefix.hex" "$work_dir/prefix.pcapng"
tshark -r "$work_dir/prefix.pcapng" -d tcp.port==443,http2 -Y http2 -V
