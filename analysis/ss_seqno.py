#!/usr/bin/env python3
"""Locate the SS packet ring in an lv1 memory dump and report its sequence numbers.

The ring is found by SIGNATURE, never by a hardcoded address -- it lives on lv1's
heap and moves between boots:

  * records are 0x50 bytes,
  * +0x00 is an SS subject id of the form 0x10??????????0001,
  * +0x20 is a sequence number that increments between adjacent records.

  ss_seqno.py <dump> [more dumps...]
"""
import struct, sys

REC = 0x50


def is_ss_id(v):
    return (v >> 56) == 0x10 and (v & 0xFFFF) == 0x0001


def scan(path):
    d = open(path, "rb").read()
    q = lambda a: struct.unpack(">Q", d[a:a + 8])[0]
    w = lambda a: struct.unpack(">I", d[a:a + 4])[0]

    # candidate record starts
    cand = [a for a in range(0, len(d) - REC, 8) if is_ss_id(q(a))]
    runs, used = [], set()
    for a in cand:
        if a in used:
            continue
        # extend forward while the next record is also SS-id'd
        seq = [a]
        b = a + REC
        while b + REC <= len(d) and is_ss_id(q(b)):
            seq.append(b); b += REC
        if len(seq) >= 2:
            s = [w(x + 0x20) for x in seq]
            # require the seqno to actually move, and stay plausible
            # keep only the leading run whose seqno advances sanely (<=64 apart)
            keep = [seq[0]]
            for i in range(1, len(seq)):
                if abs(s[i] - s[i - 1]) <= 64 and w(seq[i] + 0x28) < 0x10000:
                    keep.append(seq[i])
                else:
                    break
            ks = [w(x + 0x20) for x in keep]
            if len(keep) >= 2 and len(set(ks)) > 1:
                runs.append((keep[0], keep, ks))
                used.update(keep)
    return d, runs


def main():
    for path in sys.argv[1:]:
        d, runs = scan(path)
        print("== %s  (%d bytes)" % (path, len(d)))
        if not runs:
            print("   no SS packet ring found")
            continue
        for base, recs, seqs in runs:
            q = lambda a: struct.unpack(">Q", d[a:a + 8])[0]
            w = lambda a: struct.unpack(">I", d[a:a + 4])[0]
            print("   ring @%s  %d records  subject=%016x" % (hex(base), len(recs), q(base)))
            for r in recs:
                print("      seq=0x%-6x addr=0x%-8x len=0x%-6x" % (w(r + 0x20), w(r + 0x24), w(r + 0x28)))
            print("   MAX SEQNO = 0x%x (%d)" % (max(seqs), max(seqs)))


if __name__ == "__main__":
    main()
