#!/usr/bin/env bash
# Ralph loop for SERUM: autonomously work docs/BACKLOG.md, ONE item per iteration,
# in a fresh headless Claude Code session each time. Runs overnight; keeps the Mac
# awake; stops when the backlog is empty or after N iterations.
#
# Usage:   bash scripts/ralph_loop.sh [max_iters] [sleep_seconds]
#   e.g.   bash scripts/ralph_loop.sh 40 15
#
# Each iteration is a clean `claude -p` run given scripts/ralph_prompt.md, so
# context never bloats. Every iteration commits + pushes its own increment, so if
# you wake and stop it, no work is lost. Review progress via git log and
# docs/DEVLOG.md in the morning.
set -u

cd "$(dirname "$0")/.." || exit 1
REPO="$(pwd)"
MAX_ITERS="${1:-40}"
SLEEP_S="${2:-15}"
LOGDIR="$REPO/results/ralph"
mkdir -p "$LOGDIR"
PROMPT_FILE="$REPO/scripts/ralph_prompt.md"

if ! command -v claude >/dev/null 2>&1; then
  echo "error: 'claude' CLI not found on PATH." >&2; exit 1
fi

# keep the machine awake for the duration of this loop (macOS); harmless elsewhere
if command -v caffeinate >/dev/null 2>&1; then
  caffeinate -s -w "$$" &
fi

echo "Ralph loop starting: up to $MAX_ITERS iterations, ${SLEEP_S}s between, repo=$REPO"
for i in $(seq 1 "$MAX_ITERS"); do
  ts="$(date +%Y%m%d-%H%M%S)"
  log="$LOGDIR/iter-$(printf '%03d' "$i")-$ts.log"
  echo "=== Ralph iteration $i/$MAX_ITERS @ $ts -> $log ==="

  claude -p "$(cat "$PROMPT_FILE")" \
      --dangerously-skip-permissions \
      > "$log" 2>&1 || echo "  (claude exited non-zero; see $log)"

  if grep -q "BACKLOG EMPTY" "$log"; then
    echo "Backlog empty. Ralph loop complete after $i iteration(s)."
    break
  fi
  # brief pause so bursts of API calls settle
  sleep "$SLEEP_S"
done

echo "Ralph loop finished. Review: git log --oneline and docs/DEVLOG.md"
