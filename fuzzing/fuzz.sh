#!/usr/bin/env bash
set -euo pipefail

# Run from project root.
cd "$(dirname "$0")/.."

BIN=fuzzing/fuzz_bin
SEEDS=fuzzing/seeds
FINDINGS=fuzzing/findings

if [[ ! -x "$BIN" ]]; then
	echo "[!] $BIN missing — run fuzzing/build.sh first" >&2
	exit 1
fi

mkdir -p "$SEEDS" "$FINDINGS"
if ! ls "$SEEDS"/* >/dev/null 2>&1; then
	echo "hello" > "$SEEDS/seed1"
fi

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_AFFINITY=1

# FUZZ_STOP_ON_CRASH=1     -> exit as soon as the first crash is found.
# FUZZ_TIME=<seconds>      -> collect crashes for that many seconds, then exit.
# Both may be combined; whichever triggers first wins.
extra=()
if [[ "${FUZZ_STOP_ON_CRASH:-0}" == "1" ]]; then
	export AFL_BENCH_UNTIL_CRASH=1
fi
if [[ -n "${FUZZ_TIME:-}" ]]; then
	extra+=(-V "$FUZZ_TIME")
fi

THREADS="${THREADS:-1}"
if (( THREADS < 1 )); then THREADS=1; fi

if (( THREADS == 1 )); then
	exec afl-fuzz -i "$SEEDS" -o "$FINDINGS" "${extra[@]}" "$@" -M main -- "$BIN"
fi

pids=()
cleanup() {
	for pid in "${pids[@]}"; do
		kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for ((i = 1; i < THREADS; i++)); do
	afl-fuzz -i "$SEEDS" -o "$FINDINGS" "${extra[@]}" "$@" \
		-S "secondary$i" -- "$BIN" \
		>"$FINDINGS/secondary$i.log" 2>&1 &
	pids+=($!)
done

# Main runs in foreground; all instances share $FINDINGS so crashes land
# in $FINDINGS/<instance>/crashes/.
afl-fuzz -i "$SEEDS" -o "$FINDINGS" "${extra[@]}" "$@" -M main -- "$BIN"
