#!/bin/bash
# Port metldr's symbols to a loader build, locate verify_header, decompile.
# usage: port_all.sh <elf> <tag>
ROOT=/opt/projects/ps3
TC=$ROOT/tools/spu-toolchain/bin/spu-elf-objdump
GH=$ROOT/tools/ghidra-install/ghidra_12.1.3_PUBLIC
export JAVA_HOME=$ROOT/tools/ghidra-install/jdk-21.0.12.1+1
ELF="$1"; TAG="$2"
$TC -d "$ELF" > "$ROOT/disasm/$TAG.asm" 2>/dev/null
python3 "$ROOT/tools/spu-sleigh/xport.py" "$ROOT/disasm/metldr-v1.asm" \
        "$ROOT/disasm/$TAG.asm" "$ROOT/tools/metldr-symbols.spec" \
        "$ROOT/tools/$TAG-symbols.spec" | sed "s/^/  [$TAG] /"
python3 - "$TAG" <<'PY'
import re, sys
tag=sys.argv[1]; R='/opt/projects/ps3'
mp={}
for l in open(f'{R}/tools/{tag}-symbols.spec'):
    if not l.startswith('#'):
        f=l.split(); mp[f[1]]=int(f[0],16)
if 'ecdsa_verify' not in mp: print(f'  [{tag}] no ecdsa_verify -- skipping verify_header'); raise SystemExit
D={}
for l in open(f'{R}/disasm/{tag}.asm'):
    m=re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(\S+)\s*(.*)',l)
    if m: D[int(m.group(1),16)]=(m.group(2),m.group(3))
ev=mp['ecdsa_verify']
sites=sorted(a for a,(mn,ops) in D.items() if mn=='brsl' and f'0x{ev:x}' in ops)
if len(sites)!=1:
    print(f'  [{tag}] {len(sites)} ecdsa_verify call sites -- verify_header not auto-located'); raise SystemExit
c=sites[0]; j=c
while j>0 and D.get(j-4,('',''))[0]!='bi': j-=4
v='3-instr' if D.get(c+4,('',''))[0]=='cgti' and D.get(c+8,('',''))[0]=='nor' else \
  ('1-instr' if D.get(c+4,('',''))[0]=='rotmi' else '?')
dig=[D[k][1].split('#')[-1].strip() for k in range(j,c,4) if k in D and D[k][0]=='ila']
s=open(f'{R}/tools/{tag}-symbols.spec').read()
s=s.replace("# every entry verified: complete call sequence matches the reference\n",
  f"# every entry verified: complete call sequence matches the reference\n"
  f"# {tag}: verify_header = sole caller of ecdsa_verify (0x{c:x}); verdict {v};"
  f" digest 0x{dig[0] if dig else '?'}\n"
  f"{j:<6x} verify_header       int   void*:ctx,void*:sha_src,int:sha_len,void*:sig\n")
open(f'{R}/tools/{tag}-symbols.spec','w').write(s)
print(f'  [{tag}] verify_header 0x{j:x}  verdict {v}  digest 0x{dig[0] if dig else "?"}')
PY
rm -rf "$ROOT/tools/spu-sleigh/bench/$TAG"; mkdir -p "$ROOT/tools/spu-sleigh/bench/$TAG"
"$GH/support/analyzeHeadless" "$ROOT/tools/spu-sleigh/bench/$TAG" p -import "$ELF" \
  -processor SPU:BE:128:default -overwrite -scriptPath "$ROOT/tools/ghidra-scripts" \
  -postScript NameAndDecomp.java "$ROOT/decomp/$TAG.c" "$ROOT/tools/$TAG-symbols.spec" all \
  2>&1 | grep -oE "wrote .*" | sed "s/^/  [$TAG] /"
