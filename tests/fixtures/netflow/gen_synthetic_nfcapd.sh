#!/usr/bin/env bash
# Generate SYNTHETIC nfdump 1.7 (layout-2) NetFlow capture files for the NetFlow
# unit tests. All addresses are RFC 5737 documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or RFC 1918 private ranges
# (10.0.0.0/8); all timestamps are 2001-02-03..2001-02-10 UTC; the exporter
# Ident is "edge-router".
#
# Method: a pure-Python (stdlib only, no scapy/docker required) NetFlow v5
# encoder crafts UDP export packets with exact, deterministic First/Last
# timestamps, TCP flags and byte/packet counters, and fires them at an
# nfcapd collector (nfdump >= 1.7 binaries under $NFDUMP_PREFIX, default
# /opt/nfdump) rather than deriving flows from a packet capture: hand-crafted
# NetFlow v5 gives exact, deterministic SYN-only-vs-completed flag patterns,
# flow counts and duration/rate figures for the unit tests to assert on.
# nfcapd itself writes nfdump 1.7 layout-2 files, so the on-disk format is
# exactly what the extension reads.
#
# Writes ONLY into this script's directory (or $OUT): the nfcapd tree under
# edge-router/2001/02/, nfdump_stdout/, and scratch dirs _collect/ and _catalog/
# (removed at the end). Touches nothing else anywhere on the system.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NF="${NFDUMP_PREFIX:-/opt/nfdump}"
OUT="${OUT:-$HERE}"
TREE="$OUT/edge-router/2001/02"
PY="$HERE/gen_synthetic_nfcapd.py"
PORT="${GEN_NFCAPD_PORT:-9995}"
IDENT="edge-router"

export LD_LIBRARY_PATH="$NF/lib"
NFCAPD="$NF/bin/nfcapd"
NFDUMP="$NF/bin/nfdump"

mkdir -p "$OUT/_collect" "$OUT/_catalog" "$OUT/nfdump_stdout" "$TREE"

log() { printf '[gen] %s\n' "$*" >&2; }

require_free_port() {
  if ss -lun 2>/dev/null | grep -q ":$PORT[[:space:]]"; then
    log "ERROR: UDP port $PORT already in use; set GEN_NFCAPD_PORT to override."
    exit 1
  fi
}

# collect_bucket BUCKET FINAL_FILENAME
collect_bucket() {
  local bucket="$1" final="$2"
  local workdir="$OUT/_collect/$bucket"
  rm -rf "$workdir"
  mkdir -p "$workdir"
  local pidfile="$workdir/.nfcapd.pid"

  require_free_port
  log "starting nfcapd for bucket=$bucket on 127.0.0.1:$PORT"
  "$NFCAPD" -w "$workdir" -p "$PORT" -I "$IDENT" -D -P "$pidfile" -e -4
  sleep 1

  log "sending synthetic NetFlow v5 for bucket=$bucket"
  python3 "$PY" send "$bucket" --host 127.0.0.1 --port "$PORT" \
    --summary-json "$OUT/_catalog/${bucket}.summary.json"

  sleep 2
  local pid
  pid="$(cat "$pidfile")"
  kill "$pid"
  # wait for the process to actually exit and flush
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done

  mapfile -t produced < <(find "$workdir" -maxdepth 1 -type f -name 'nfcapd.[0-9]*' | sort)
  if [ "${#produced[@]}" -ne 1 ]; then
    log "ERROR: expected exactly 1 output file for bucket=$bucket, got: ${produced[*]:-<none>}"
    exit 1
  fi
  local produced_file="${produced[0]}"

  local magic
  magic="$(xxd -p -l4 "$produced_file")"
  if [ "$magic" != "0ca50200" ]; then
    log "WARNING: magic for $produced_file was $magic, expected 0ca50200 (layout 2)."
    log "Rewriting via nfdump -r/-w to force layout 2."
    local fixed="$workdir/fixed.$bucket"
    "$NFDUMP" -r "$produced_file" -w "$fixed" 'any'
    mv -f "$fixed" "$produced_file"
    magic="$(xxd -p -l4 "$produced_file")"
    [ "$magic" = "0ca50200" ] || { log "ERROR: still not layout 2 after rewrite."; exit 1; }
  fi

  mv -f "$produced_file" "$TREE/$final"
  python3 "$PY" normalize "$TREE/$final" >&2
  log "bucket=$bucket -> $TREE/$final ($(stat -c%s "$TREE/$final") bytes, magic $magic)"
}

capture_nfdump_stdout() {
  log "capturing nfdump_stdout/ fixtures with $NFDUMP"
  local sd="$OUT/nfdump_stdout"
  mkdir -p "$sd"
  local dr=(env TZ=UTC LD_LIBRARY_PATH="$NF/lib" "$NFDUMP")
  local f="$TREE/nfcapd.200102030000"
  local nets_src="(src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16)"
  local nets_dst="(dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16)"

  "${dr[@]}" -r "$f" -s ip/flows -n 5 -N -6 -q -o csv -- any > "$sd/stat_ip.txt"
  "${dr[@]}" -r "$f" -s dstport:p/flows -n 5 -N -6 -q -o csv -- any > "$sd/stat_port_p.txt"
  "${dr[@]}" -r "$f" -s srcip/bytes -s dstport:p/flows -n 5 -N -6 -q -o csv -- any > "$sd/stat_multi.txt"
  "${dr[@]}" -r "$f" -A srcip,dstip,dstport,flags -s record/flows -n 5 -N -6 -q \
    -o "csv:%tsr,%ter,%sa,%da,%dp,%flg,%pkt,%byt,%fl" -- any > "$sd/agg_flags.txt"
  "${dr[@]}" -r "$f" -A srcip,dstip -s record/bytes -n 5 -N -6 -q \
    -o "csv:%tsr,%ter,%sa,%da,%pkt,%byt,%bps,%bpp,%fl" -- any > "$sd/agg_plain.txt"
  "${dr[@]}" -r "$f" -c 20 -N -6 -q \
    -o "csv:%tsr,%ter,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt" -- any > "$sd/raw.txt"
  "${dr[@]}" -r "$f" -A srcip4/24,dstip4/24 -s record/flows -n 5 -N -6 -q \
    -o "csv:%tsr,%ter,%sa,%da,%pkt,%byt,%fl" -- any > "$sd/seg24.txt"
  "${dr[@]}" -I -r "$f" > "$sd/dash_I.txt"
  "${dr[@]}" -r "$f" -c 20 -N -6 -q \
    -o "csv:%tsr,%ter,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt" -- "src ip 192.0.2.99" > "$sd/no_match.txt"
  "${dr[@]}" -r "$f" -s ip/flows -n 5 -N -6 -q -o csv -- "src ip 192.0.2.99" > "$sd/no_match_stat.txt"
  set +e
  "${dr[@]}" -r "$f" -N -6 -q -o csv -- "src ip 192.0.2.99 and" > "$sd/exit254.txt"
  "${dr[@]}" -r "$f" -A srcip,dstip -s record/flows -n 5 -N -6 -q \
    -o "csv:%tsr,%ter,%sa,%da,%flg,%pkt,%byt,%fl" -- any > "$sd/flg_stderr.txt" 2>"$sd/.flg_stderr.tmp"
  set -e
  mv -f "$sd/.flg_stderr.tmp" "$sd/flg_stderr.txt"
  # the exact run_netflow_sweep argv (ports 445,3389; default internal nets)
  "${dr[@]}" -r "$f" -A srcip,dstip,dstport,flags -s record/flows -n 50000 -N -6 -q \
    -o "csv:%tsr,%ter,%sa,%da,%dp,%flg,%pkt,%byt,%fl" -- \
    "proto tcp and flags S and dst port in [ 445 3389 ] and $nets_src and $nets_dst" > "$sd/sweep.txt"
  # the exact run_netflow_pair_timeline argvs over both daily files (staged like the tool):
  # the SYN-only retry pair, the long session's pair, and the latter with both_directions=True
  local stage raw="csv:%tsr,%ter,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt"
  stage="$(mktemp -d)"
  ln -s "$TREE/nfcapd.200102030000" "$stage/000000"
  ln -s "$TREE/nfcapd.200102040000" "$stage/000001"
  "${dr[@]}" -R "$stage" -c 20001 -N -6 -q -o "$raw" -- \
    "src ip 10.0.5.83 and dst ip 192.0.2.150 and dst port 993" > "$sd/pair_retries.txt"
  "${dr[@]}" -R "$stage" -c 20001 -N -6 -q -o "$raw" -- \
    "src ip 10.0.2.37 and dst ip 203.0.113.77 and dst port 40519" > "$sd/pair_session.txt"
  "${dr[@]}" -R "$stage" -c 20001 -N -6 -q -o "$raw" -- \
    "((src ip 10.0.2.37 and dst ip 203.0.113.77 and dst port 40519) or (src ip 203.0.113.77 and dst ip 10.0.2.37 and src port 40519))" \
    > "$sd/pair_session_both.txt"
  rm -rf "$stage"
  # pair_session_both.txt gets the long session's reply leg (75 B/s) and its exporter copy
  # (+2 % bytes) right after the session record (the corpus has no reply records)
  python3 - "$sd/pair_session_both.txt" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
out, done = [lines[0]], False
for line in lines[1:]:
    out.append(line)
    f = line.split(",")
    if not done and f[7] == "...AP.SF":
        first, last, pr, sa, sp, da, dp, flg, pkt, _byt = f
        reply = 75 * round(float(last) - float(first))
        for byt in (reply, reply + max(1, round(reply * 0.02))):
            out.append(",".join([first, last, pr, da, dp, sa, sp, flg, pkt, str(byt)]))
        done = True
assert done, "no session record in the capture"
open(sys.argv[1], "w").write("\n".join(out) + "\n")
PY
  # the exact run_netflow_host_profile passes for 10.0.2.37 (4 tables each)
  "${dr[@]}" -r "$f" -s srcip/flows -s dstport:p/flows -s dstip/flows -s dstip/bytes -n 20 \
    -N -6 -q -o csv -- "src ip 10.0.2.37" > "$sd/profile_out.txt"
  "${dr[@]}" -r "$f" -s dstip/flows -s dstport:p/flows -s srcip/flows -s srcip/bytes -n 20 \
    -N -6 -q -o csv -- "dst ip 10.0.2.37" > "$sd/profile_in.txt"
  # -A / -s record/* modes print only the sentinel when nothing matches (no header)
  "${dr[@]}" -r "$f" -A srcip,dstip,dstport -s record/flows -n 20 -N -6 -q \
    -o "csv:%tsr,%ter,%sa,%da,%dp,%pkt,%byt,%bps,%bpp,%fl" -- "src ip 192.0.2.99" \
    > "$sd/no_match_agg.txt"
  log "nfdump_stdout/ capture complete."
}

main() {
  collect_bucket day1  nfcapd.200102030000
  collect_bucket day2  nfcapd.200102040000
  collect_bucket tiny3 nfcapd.200102100600
  # the two strays next to the nfcapd files: a 0-byte file and a text file with a
  # rotation-style name (neither is a NetFlow capture)
  : > "$OUT/edge-router/zero-length"
  printf 'not a netflow file\n' > "$TREE/nfcapd.200102035555"

  log "done. Files:"
  ls -la "$TREE"/nfcapd.* >&2

  capture_nfdump_stdout

  rm -rf "$OUT/_collect" "$OUT/_catalog"
  log "See README.md next to this script for the corpus and the exact capture commands."
}

main "$@"
