#!/bin/bash
# Re-decompile metldr with the confirmed symbol names applied.
# usage: apply_symbols.sh [out.c]
set -e
ROOT=/opt/projects/ps3
GH="$ROOT/tools/ghidra-install/ghidra_12.1.3_PUBLIC"
export JAVA_HOME="$ROOT/tools/ghidra-install/jdk-21.0.12.1+1"
OUT="${1:-$ROOT/decomp/metldr.c}"
PROJ="$ROOT/tools/spu-sleigh/bench/sym"
rm -rf "$PROJ"; mkdir -p "$PROJ"
"$GH/support/analyzeHeadless" "$PROJ" s -import "$ROOT/nordumps/metldr" \
  -processor SPU:BE:128:default -loader BinaryLoader -loader-baseAddr 0x0 -overwrite \
  -scriptPath "$ROOT/tools/ghidra-scripts" \
  -postScript NameAndDecomp.java "$OUT" "$ROOT/tools/metldr-symbols.spec" all \
  2>&1 | grep -E "wrote|FAILED at" || true
wc -l "$OUT"
