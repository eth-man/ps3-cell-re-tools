#!/bin/bash
# verifygate -- which byte of the ctx+0xE0 flag quadword gates appldr's VERIFY?
#
# Produced F-0129. A hand-decode of `rotqbyi ,6` suggests ctx+0xE6. It is
# wrong: xsbh takes the ODD byte of each halfword and brhz tests the
# PREFERRED-SLOT halfword, so the tested byte is +0xE9. Hand-tracing was wrong
# three times in this investigation, so it is measured, one flag at a time.
#
#   usage: verifygate.sh [-v VERSION] [byte ...]    default: -v 493, none 6 9 8 7
#
# Needs, supplied by you:
#   $PS3_CORPUS   directory of decrypted modules, containing appldr-493.elf
#   $ANERGISTIC   the emulator binary (default: ../anergistic/anergistic)
set -u
CORPUS=${PS3_CORPUS:?set PS3_CORPUS to your decrypted-module directory}
ANERG=${ANERGISTIC:-$(dirname "$0")/../anergistic/anergistic}
VER=493
if [ "${1:-}" = "-v" ]; then VER=$2; shift 2; fi

# Select the appldr BY VERSION and refuse to guess. An earlier draft used a
# loose `find` and silently picked corpus/356/appldr.elf -- a 3.56 module --
# for a 4.93 expectation, producing a wrong answer that looked like a broken
# finding. A harness that quietly substitutes a different artifact is worse
# than one that does not run.
ELF=""
for cand in \
    "$CORPUS/loaders-$VER/appldr-$VER.elf" \
    "$CORPUS/appldr-$VER.elf" \
    "$CORPUS/$VER/appldr.elf" \
    "$CORPUS/${VER:0:1}.${VER:1}/appldr.elf" \
    "$CORPUS/../loaders-$VER/appldr-$VER.elf" \
    "$CORPUS/corpus/$VER/appldr.elf"; do
  [ -f "$cand" ] && { ELF="$cand"; break; }
done
if [ -z "$ELF" ]; then
  echo "verifygate: no appldr for version $VER under $CORPUS" >&2
  echo "            looked for loaders-$VER/appldr-$VER.elf, appldr-$VER.elf," >&2
  echo "            $VER/appldr.elf. Refusing to substitute another version." >&2
  exit 2
fi
echo "  using $ELF" >&2
[ -x "$ANERG" ] || { echo "verifygate: no anergistic at $ANERG" >&2; exit 2; }

CTX=0x3c000
VERIFY=0x160c0            # reached => verification RUNS
CTXBIN=$(mktemp -t verifygate-ctx.XXXXXX)
trap 'rm -f "$CTXBIN"' EXIT

for b in "${@:-none 6 9 8 7}"; do
  python3 - "$b" "$CTXBIN" <<'PY'
import sys
buf = bytearray(0x1000)
if sys.argv[1] != 'none':
    buf[0xE0 + int(sys.argv[1], 16)] = 1
open(sys.argv[2], 'wb').write(buf)
PY
  out=$(ANERG_STOP_PC=$VERIFY ANERG_MAXI=200000 \
        "$ANERG" -p 0x166f4 -r 81=$CTX -r 1=0x3dfa0 \
                 -L "$CTXBIN@$CTX" -m 200000 "$ELF" 2>&1)
  if echo "$out" | grep -q "\[RESULT\]"; then v="runs"; else v="skipped"; fi
  if [ "$b" = none ]; then lbl="all flags zero"; else lbl="ctx+0xE$b = 1"; fi
  printf "  %-16s -> verify %s\n" "$lbl" "$v"
done
