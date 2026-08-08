#!/usr/bin/env bash
# Packaging smoke test: the MCP entrypoint actually starts, and - when a host MCP
# inventory is supplied - that inventory registers this server.
#
# LAYOUT-AGNOSTIC: the entrypoint is derived from this script's OWN location
# (test/install.smoke.sh -> ../src/mcp.ts), so the smoke works from any clone path.
# The registration check is OPTIONAL and only runs when TOML is passed (or the
# default path happens to exist), because where a host keeps its MCP inventory is
# not this repo's business.
#
#   bash test/install.smoke.sh                       # entrypoint check only
#   TOML=~/path/to/servers.toml bash test/...        # + registration check
#
# NOT `set -e`: every check captures first, then tests an exit code it owns, so a
# failure is reported with a FAIL line rather than dying silently mid-pipe. Never
# gate a && chain on a piped command here - a pipeline's status is the LAST
# command's, not the one being checked.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SRC="${SRC:-$REPO/src/mcp.ts}"
TOML="${TOML:-}"
BUN="${BUN:-$HOME/.bun/bin/bun}"
FAILED=0

fail() { echo "FAIL: $*"; FAILED=1; }

# ---------- 1: registered in the host's MCP inventory (optional) ----------
if [ -z "$TOML" ]; then
  echo "  skip: no TOML given, host MCP registration not checked (pass TOML=<servers.toml>)"
elif [ ! -f "$TOML" ]; then
  # An explicitly-passed path that does not exist IS a failure - the caller asked
  # for the check.
  fail "servers.toml not found at $TOML"
else
  grep -q '^\[servers\."agentic-password-injector"\]$' "$TOML"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "[servers.\"agentic-password-injector\"] not in $TOML"
  else
    echo "  ok: servers.toml entry present"
  fi
  grep -q 'src/mcp\.ts' "$TOML"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "servers.toml entry does not point at src/mcp.ts"
  else
    echo "  ok: servers.toml args point at src/mcp.ts"
  fi
fi

# ---------- 2: the entrypoint starts and stays up ----------
if [ ! -f "$SRC" ]; then
  fail "entrypoint missing: $SRC"
elif [ ! -x "$BUN" ] && ! command -v "$BUN" >/dev/null 2>&1; then
  fail "bun not available at $BUN"
else
  LOG="$(mktemp)"
  # stdin must stay OPEN: a stdio MCP server shuts down cleanly on stdin EOF, so
  # `</dev/null` makes a perfectly healthy server look like an instant exit. A
  # FIFO held open by this script's own fd 3 is the cheapest never-EOF stdin.
  FIFO_DIR="$(mktemp -d)"
  FIFO="$FIFO_DIR/stdin"
  mkfifo "$FIFO"
  # `3<>` (read-write), never a bare `3>`: opening a FIFO write-only BLOCKS until
  # a reader shows up, and the reader is the process we have not started yet.
  exec 3<>"$FIFO"
  "$BUN" "$SRC" >"$LOG" 2>&1 <"$FIFO" &
  PID=$!
  sleep 1
  # A crash-on-start has already reaped the process by now; a healthy stdio
  # server is still sitting on stdin.
  if kill -0 "$PID" 2>/dev/null; then
    echo "  ok: src/mcp.ts started and was still alive after 1s"
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
  else
    wait "$PID" 2>/dev/null
    rc=$?
    fail "src/mcp.ts exited immediately (rc=$rc)"
    echo "  --- output ---"
    tail -20 "$LOG" | sed 's/^/  /'
  fi
  exec 3>&-
  rm -f "$LOG"
  rm -rf "$FIFO_DIR"
fi

if [ "$FAILED" -eq 0 ]; then
  echo "OK"
  exit 0
fi
echo "SMOKE TEST FAILED"
exit 1
