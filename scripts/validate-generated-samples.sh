#!/usr/bin/env bash
set -euo pipefail

keep_samples=0

usage() {
  cat <<'USAGE'
Usage: scripts/validate-generated-samples.sh [--keep-samples]

Generate fresh parser samples with the supported security tools and validate them
through parsex CLI parser selection.

Options:
  --keep-samples  keep the temporary sample directory for inspection
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-samples)
      keep_samples=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
parsex_bin="$tmp_dir/parsex"
fixture_server_pid=""
fixture_url=""

export GOCACHE="${GOCACHE:-$tmp_dir/go-build}"

cleanup() {
  if [[ -n "$fixture_server_pid" ]]; then
    kill "$fixture_server_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$keep_samples" -eq 1 ]]; then
    echo "generated samples kept at $tmp_dir"
    return
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

log() {
  printf '==> %s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  local tool="$1"
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required to generate parser samples"
}

start_fixture_server() {
  if [[ -n "$fixture_url" ]]; then
    return 0
  fi

  require_tool python3

  local web_root="$tmp_dir/web"
  mkdir -p "$web_root"
  printf 'parsex-generated\n' > "$web_root/generated"

  local port
  if ! port="$(python3 - 2>"$tmp_dir/fixture-port.err" <<'PORTPY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PORTPY
)"; then
    sed -n '1,80p' "$tmp_dir/fixture-port.err" >&2
    fail "local HTTP fixture could not reserve a port"
  fi

  python3 -m http.server "$port" --bind 127.0.0.1 --directory "$web_root" >/dev/null 2>&1 &
  fixture_server_pid="$!"
  fixture_url="http://127.0.0.1:$port"

  require_tool curl
  for _ in {1..20}; do
    if curl -fsS "$fixture_url/generated" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done

  fail "local HTTP fixture did not become ready"
}

generate_nmap_samples() {
  require_tool nmap

  log "generating nmap samples with nmap"
  if ! nmap -sT -Pn -p 1,80 --host-timeout 30s -oA "$tmp_dir/nmap-generated" 127.0.0.1 >/dev/null 2>"$tmp_dir/nmap.err"; then
    sed -n '1,80p' "$tmp_dir/nmap.err" >&2
    fail "nmap failed to generate samples"
  fi

  cp "$tmp_dir/nmap-generated.nmap" "$tmp_dir/nmap-standard"
  cp "$tmp_dir/nmap-generated.xml" "$tmp_dir/nmap-xml"
  cp "$tmp_dir/nmap-generated.gnmap" "$tmp_dir/nmap-grepable"
}

generate_nuclei_samples() {
  require_tool nuclei
  start_fixture_server

  log "generating nuclei samples with nuclei"
  local template="$tmp_dir/nuclei-template.yaml"
  cat > "$template" <<'EOF'
id: generated-parsex-check

info:
  name: Generated Parsex Check
  author: parsex
  severity: info
  tags: generated,parsex

http:
  - method: GET
    path:
      - "{{BaseURL}}/generated"
    matchers:
      - type: word
        words:
          - "parsex-generated"
EOF

  if ! nuclei -u "$fixture_url" -t "$template" -jsonl -silent -disable-update-check -o "$tmp_dir/nuclei-json" >/dev/null 2>"$tmp_dir/nuclei-json.err"; then
    sed -n '1,80p' "$tmp_dir/nuclei-json.err" >&2
    fail "nuclei failed to generate JSONL sample"
  fi
  if [[ ! -s "$tmp_dir/nuclei-json" ]]; then
    fail "nuclei JSONL sample is empty"
  fi

  if ! nuclei -u "$fixture_url" -t "$template" -silent -disable-update-check -o "$tmp_dir/nuclei-standard" >/dev/null 2>"$tmp_dir/nuclei-standard.err"; then
    sed -n '1,80p' "$tmp_dir/nuclei-standard.err" >&2
    fail "nuclei failed to generate standard sample"
  fi
  if [[ ! -s "$tmp_dir/nuclei-standard" ]]; then
    fail "nuclei standard sample is empty"
  fi
}

generate_ffuf_samples() {
  require_tool ffuf
  start_fixture_server

  log "generating ffuf samples with ffuf"
  local wordlist="$tmp_dir/ffuf-wordlist.txt"
  printf 'generated\nmissing\n' > "$wordlist"

  if ! ffuf -w "$wordlist" -u "$fixture_url/FUZZ" -mc all -t 1 -timeout 5 -of json -o "$tmp_dir/ffuf-json" >/dev/null 2>"$tmp_dir/ffuf-json.err"; then
    sed -n '1,80p' "$tmp_dir/ffuf-json.err" >&2
    fail "ffuf failed to generate JSON sample"
  fi
  if [[ ! -s "$tmp_dir/ffuf-json" ]]; then
    fail "ffuf JSON sample is empty"
  fi

  if ! ffuf -w "$wordlist" -u "$fixture_url/FUZZ" -mc all -t 1 -timeout 5 > "$tmp_dir/ffuf-standard" 2>"$tmp_dir/ffuf-standard.err"; then
    sed -n '1,80p' "$tmp_dir/ffuf-standard.err" >&2
    fail "ffuf failed to generate standard sample"
  fi
  if [[ ! -s "$tmp_dir/ffuf-standard" ]]; then
    fail "ffuf standard sample is empty"
  fi
}

validate_sample() {
  local parser="$1"
  local sample="$2"
  local output="$tmp_dir/$parser.output.json"

  log "validating $parser"
  "$parsex_bin" --input "$sample" --parser "$parser" > "$output"

  if ! grep -F "\"parser\": \"$parser\"" "$output" >/dev/null; then
    sed -n '1,80p' "$output" >&2
    fail "$parser did not produce the expected parser name"
  fi

  if ! grep -F "\"compatible_parsers\"" "$output" >/dev/null; then
    sed -n '1,80p' "$output" >&2
    fail "$parser output did not include compatible_parsers"
  fi
}

cd "$repo_root"

log "building parsex CLI"
go build -o "$parsex_bin" ./cmd/parsex

log "generating fresh parser samples in $tmp_dir"
generate_nmap_samples
generate_nuclei_samples
generate_ffuf_samples

validate_sample nmap-standard "$tmp_dir/nmap-standard"
validate_sample nmap-xml "$tmp_dir/nmap-xml"
validate_sample nmap-grepable "$tmp_dir/nmap-grepable"
validate_sample nuclei-json "$tmp_dir/nuclei-json"
validate_sample nuclei-standard "$tmp_dir/nuclei-standard"
validate_sample ffuf-json "$tmp_dir/ffuf-json"
validate_sample ffuf-standard "$tmp_dir/ffuf-standard"

log "all generated parser samples validated"
