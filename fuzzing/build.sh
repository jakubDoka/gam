#!/usr/bin/env bash
set -euo pipefail

# Run from project root.
cd "$(dirname "$0")/.."

OUT_DIR=fuzzing
LL="$OUT_DIR/fuzzing.ll"
OBJ="$OUT_DIR/fuzz.o"
BIN="$OUT_DIR/fuzz_bin"
LIBS="lib/libsqlite.a"

echo "[*] Emitting Odin LLVM IR..."
# odin emits "<package>.ll" into CWD regardless of -out:, so do it from OUT_DIR.
(
	cd "$OUT_DIR"
	odin build . \
		-build-mode:llvm-ir \
		-no-entry-point \
		-default-to-nil-allocator \
		-no-bounds-check \
		-define:FUZZING=true \
		-o:speed
)
[[ -f "$LL" ]] || { echo "missing $LL"; ls -1 "$OUT_DIR"; exit 1; }

echo "[*] Compiling IR with afl-clang-fast for coverage..."
export AFL_LLVM_LAF_ALL=1
afl-clang-fast -O2 -c "$LL" -o "$OBJ"

echo "[*] Linking AFL++ harness..."
afl-clang-fast -O2 fuzzing/harness.c "$OBJ" $LIBS -lm -o "$BIN"

echo "[+] Built $BIN"
