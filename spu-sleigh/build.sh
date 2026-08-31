#!/bin/bash
# Compile the SPU SLEIGH spec from ./<variant>/ and install it into Ghidra.
# usage: build.sh [variant]        (default: work)
set -e
VARIANT="${1:-work}"
ROOT=/opt/projects/ps3/tools
GHIDRA="$ROOT/ghidra-install/ghidra_12.1.3_PUBLIC"
LANG_DIR="$GHIDRA/Ghidra/Processors/SPU/data/languages"
SRC="$ROOT/spu-sleigh/$VARIANT"
export JAVA_HOME="$ROOT/ghidra-install/jdk-21.0.12.1+1"
export PATH="$JAVA_HOME/bin:$PATH"

[ -d "$SRC" ] || { echo "no such variant: $SRC"; exit 1; }
cp "$SRC"/spu.sinc "$SRC"/spu.slaspec "$SRC"/spu.cspec "$SRC"/spu.ldefs \
   "$SRC"/spu.pspec "$SRC"/spu.opinion "$SRC"/spu.dwarf "$LANG_DIR"/
rm -f "$LANG_DIR/spu.sla"
"$GHIDRA/support/sleigh" -a "$LANG_DIR" 2>&1 | grep -vi "NOP constructor" | tail -30
[ -f "$LANG_DIR/spu.sla" ] || { echo "BUILD FAILED: no spu.sla"; exit 1; }
echo "installed $VARIANT -> $LANG_DIR ($(stat -c%s "$LANG_DIR/spu.sla") bytes)"
