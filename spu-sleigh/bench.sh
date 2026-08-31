#!/bin/bash
# Decompile a fixed target set with the currently-installed SPU spec and score it.
# usage: bench.sh <tag>
set -e
TAG="${1:?usage: bench.sh <tag>}"
ROOT=/opt/projects/ps3
GHIDRA="$ROOT/tools/ghidra-install/ghidra_12.1.3_PUBLIC"
export JAVA_HOME="$ROOT/tools/ghidra-install/jdk-21.0.12.1+1"
BENCH="$ROOT/tools/spu-sleigh/bench"
PROJ="$BENCH/proj"
OUT="$BENCH/$TAG"
rm -rf "$PROJ" "$OUT"; mkdir -p "$PROJ" "$OUT"

# metldr is a raw LS image; the loaders are real SPU ELFs.
run_raw () {  # name file
  "$GHIDRA/support/analyzeHeadless" "$PROJ" b -import "$2" -processor SPU:BE:128:default \
    -loader BinaryLoader -loader-baseAddr 0x0 -overwrite \
    -scriptPath "$ROOT/tools/ghidra-scripts" -postScript DumpFuncs.java "$OUT/$1.c" \
    > "$OUT/$1.log" 2>&1 || true
}
run_elf () {
  "$GHIDRA/support/analyzeHeadless" "$PROJ" b -import "$2" -processor SPU:BE:128:default \
    -overwrite -scriptPath "$ROOT/tools/ghidra-scripts" \
    -postScript DumpFuncs.java "$OUT/$1.c" > "$OUT/$1.log" 2>&1 || true
}

t0=$(date +%s)
run_raw metldr  "$ROOT/nordumps/metldr"
run_elf isoldr  "$ROOT/extracted/corpus/355/isoldr.elf"
run_elf lv1ldr  "$ROOT/extracted/corpus/493/lv1ldr.elf"
t1=$(date +%s)
echo "wall: $((t1-t0))s"
python3 "$ROOT/tools/spu-sleigh/metrics.py" "$OUT"/*.c | tee "$OUT/metrics.json"
