#!/bin/bash
# Re-decompile every SPU module in the corpus with the current spec.

ROOT=/opt/projects/ps3
GH="$ROOT/tools/ghidra-install/ghidra_12.1.3_PUBLIC"
export JAVA_HOME="$ROOT/tools/ghidra-install/jdk-21.0.12.1+1"
PROJ="$ROOT/tools/spu-sleigh/bench/redecomp"
rm -rf "$PROJ"; mkdir -p "$PROJ"
run () {
  echo "--- $1"
  "$GH/support/analyzeHeadless" "$PROJ" r -import "$2" -processor SPU:BE:128:default \
     ${3:+-loader BinaryLoader -loader-baseAddr 0x0} -overwrite \
     -scriptPath "$ROOT/tools/ghidra-scripts" -postScript DumpFuncs.java "$ROOT/decomp/$1.c" \
     > /dev/null 2>&1 || echo "  FAILED"
  [ -f "$ROOT/decomp/$1.c" ] && wc -l "$ROOT/decomp/$1.c"
}
run metldr               "$ROOT/nordumps/metldr" raw
run appldr               "$ROOT/extracted/loaders-493/appldr-493.elf"
run isoldr               "$ROOT/extracted/corpus/355/isoldr.elf"
run lv1ldr               "$ROOT/extracted/loaders-493/lv1ldr-493.elf"
run lv2ldr               "$ROOT/extracted/loaders-493/lv2ldr-493.elf"
run sv_iso_spu_module    "$ROOT/extracted/corpus/493/sv_iso_spu_module.elf"
run sb_iso_spu_module    "$ROOT/extracted/corpus/493/sb_iso_spu_module.elf"
run sc_iso               "$ROOT/extracted/corpus/493/sc_iso.elf"
run spu_token_processor  "$ROOT/extracted/corpus/493/spu_token_processor.elf"
run spu_utoken_processor "$ROOT/extracted/corpus/493/spu_utoken_processor.elf"
run spu_pkg_rvk_verifier "$ROOT/extracted/corpus/493/spu_pkg_rvk_verifier.elf"
