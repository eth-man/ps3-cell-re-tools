#!/usr/bin/env python3
"""notedb -- a queryable index over notes/, with SUPERSESSION as data.

WHY THIS EXISTS (2026-09-02).  The notes are an append-only log and they are correct;
what kept failing was the hand-written memory layer summarising them, plus a purely
LEXICAL recall hook.  On 2026-09-01/02 a session burned SIX console power-cycles
re-deriving results that notes/163, /165, /166 and /179 already held, because:

  * nothing encoded that notes/166 OVERTURNS notes/165 (one day apart) -- both read as
    equally true, and the older one got quoted as current fact;
  * "closed / retracted / superseded" lived in prose, so nothing could answer the only
    question that mattered: *what is the CURRENT verdict on this route?*;
  * recall.py greps words: the notes that closed the route say "ss_server", "Rank-2",
    "spuprobe", "mailbox" -- never "0x10043" -- so a keyword search for the route
    returned every note EXCEPT the ones that killed it.

So this indexes three things the flat files cannot express: per-note STATUS, the
supersession GRAPH, and shared ENTITIES (hex addresses, which are this project's real
join key -- vocabulary drifts, 0x2b80a8 does not).

    python3 tools/notedb.py build            # (re)build data/notes.db from notes/
    python3 tools/notedb.py verdict <term>   # CURRENT verdict: live notes first,
                                             #   superseded ones shown as struck
    python3 tools/notedb.py addr 0x2b80a8    # every note touching an address
    python3 tools/notedb.py show 166         # one note: status, refs, what it overturns
    python3 tools/notedb.py stale            # notes superseded by a later note
"""
import sys, os, re, sqlite3, glob

# Expects a sibling notes/ directory of "NNN-title.md" files, one append-only note per
# finding, where later notes retract earlier ones in prose.  That is the convention this
# was written against; adjust NOTES/DB if yours differs.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTES = os.path.join(ROOT, 'notes')
DB    = os.path.join(ROOT, 'data', 'notes.db')

# A "notes/NNN" reference is an OVERTURN only when an overturning verb PRECEDES it
# closely and is aimed at it -- e.g. "RETRACTED: notes/165 said ...", "corrects notes/79".
# v1 accepted any such word within +-160 chars, which produced two false-edge classes:
#   * a note merely DISCUSSING a retraction ("notes/165 ... this is EXACTLY the notes/112
#     hazard") marked notes/112 as overturned;
#   * tonight's own write-up, which quotes every note it read, appeared to supersede all
#     of them -- so notes/163 showed as superseded by the note that was AGREEING with it.
# Now: the verb must appear in the <=60 chars immediately BEFORE the reference, with no
# other note reference in between (so "corrects notes/A ... notes/B" does not hit B).
OVERTURN = re.compile(r'\b(retracts?|retracted|retraction|corrects?|corrected|correction|'
                      r'supersedes?|superseded|withdraws?|withdrawn|overturn\w*|'
                      r'refut\w+|premature)\b', re.I)
# Per-note status, strongest first.
STATUS_PATTERNS = [
    ('retracted',  re.compile(r'^\s*#{1,3}.*\bRETRACT', re.I|re.M)),
    ('corrected',  re.compile(r'\[CORRECTED[^\]]*\]|^\s*#{1,3}.*\bCORRECTION\b', re.I|re.M)),
    # 'closed' must cover how this corpus ACTUALLY writes a closure.  v1 keyed on the
    # literal word CLOSED and so read notes/163 ("PIVOT to the legitimate ss_server
    # entry", "R3 -- do NOT attempt") and notes/166 ("Rank-2 'idle SPE' premise
    # weakened", "guest SPEs aren't safely probeable") as merely 'negative' -- and those
    # two are precisely the notes that closed the route a session then spent six console
    # power-cycles re-deriving.  A closure here is a DECISION TO STOP, however phrased.
    ('closed',     re.compile(r'\b(is|are|now)\s+CLOSED\b|^\s*#{1,3}.*\bCLOSED\b|'
                              r'\bDEAD END\b|\bEXHAUSTED\b|'
                              r'\bPIVOT\b|\bdo NOT attempt\b|\bpremise weakened\b|'
                              # NOT bare 'unreachable': it describes addresses, polls and
                              # CPU modes far more often than a closed route (it wrongly
                              # flagged notes/157, /174, /186).  Decision language only.
                              r'\bthe wall is real\b|\bruled out\b|'
                              r'\bnot viable\b|\bdo not re-?open\b|\bDO NOT RETRY\b|'
                              r"\bn't safely\b|\bno spare\b|\bABANDON\w*\b", re.I|re.M)),
    ('negative',   re.compile(r'\bhonest negative\b|\bdoes NOT\b|\bNEGATIVE\b', re.I)),
    ('open',       re.compile(r'\bOPEN, not closed\b|\bstill OPEN\b|\bUNRESOLVED\b', re.I)),
]
ADDR = re.compile(r'\b(?:0x)?([0-9a-f]{5,8})\b', re.I)
NREF = re.compile(r'notes?/(\d{1,3})')

def note_files():
    out=[]
    for p in sorted(glob.glob(os.path.join(NOTES,'*.md'))):
        m=re.match(r'(\d{1,3})-', os.path.basename(p))
        if m: out.append((int(m.group(1)), p))
    return out

def status_of(text):
    for name,pat in STATUS_PATTERNS:
        if pat.search(text): return name
    return 'info'

def build():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    if os.path.exists(DB): os.remove(DB)
    db=sqlite3.connect(DB); c=db.cursor()
    c.executescript("""
    CREATE TABLE notes(id INTEGER PRIMARY KEY, title TEXT, date TEXT, path TEXT,
                       status TEXT, body TEXT);
    CREATE TABLE refs(src INTEGER, dst INTEGER, kind TEXT, context TEXT);
    CREATE TABLE ents(note INTEGER, kind TEXT, val TEXT);
    CREATE INDEX ents_val ON ents(val);
    CREATE INDEX refs_dst ON refs(dst, kind);
    CREATE VIRTUAL TABLE ft USING fts5(title, body, content='');
    """)
    for nid, path in note_files():
        text=open(path, errors='replace').read()
        head=text.split('\n',1)[0]
        title=re.sub(r'^#\s*notes?/\d+\s*[-—:]*\s*','',head).strip()
        m=re.search(r'(?:Date:\s*)?(20\d\d-\d\d-\d\d)', text[:400])
        date=m.group(1) if m else ''
        c.execute("INSERT INTO notes VALUES(?,?,?,?,?,?)",
                  (nid,title,date,os.path.relpath(path,ROOT),status_of(text),text))
        c.execute("INSERT INTO ft(rowid,title,body) VALUES(?,?,?)",(nid,title,text))
        # entities: hex addresses are the stable join key across vocabulary drift
        for a in set(x.lower() for x in ADDR.findall(text)):
            c.execute("INSERT INTO ents VALUES(?,?,?)",(nid,'addr','0x'+a.lstrip('0').zfill(4)))
        # cross references, classified by the words IMMEDIATELY BEFORE them.
        # Deduped per (src,dst,kind): a note citing another twenty times is one edge, and
        # v1's duplicates made "SUPERSEDED by notes/185, notes/185, notes/185" output.
        seen=set()
        for mm in NREF.finditer(text):
            dst=int(mm.group(1))
            if dst==nid: continue
            pre=text[max(0,mm.start()-60):mm.start()]
            if NREF.search(pre):                      # another ref sits between verb and us
                pre=pre[NREF.search(pre).end():]
            kind='supersedes' if OVERTURN.search(pre) else 'cites'
            # a note can only overturn an EARLIER one; the log is append-only
            if kind=='supersedes' and dst>=nid: kind='cites'
            key=(dst,kind)
            if key in seen: continue
            seen.add(key)
            ctx=text[max(0,mm.start()-160):mm.end()+160].replace('\n',' ')
            c.execute("INSERT INTO refs VALUES(?,?,?,?)",(nid,dst,kind,ctx.strip()[:300]))
    db.commit()
    n=c.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    s=c.execute("SELECT COUNT(*) FROM refs WHERE kind='supersedes'").fetchone()[0]
    print("indexed %d notes, %d supersession edges -> %s"%(n,s,os.path.relpath(DB,ROOT)))
    db.close()

def _conn():
    if not os.path.exists(DB): sys.exit("no index; run: python3 tools/notedb.py build")
    return sqlite3.connect(DB)

def superseded_by(c, nid):
    return [r[0] for r in c.execute(
        "SELECT DISTINCT src FROM refs WHERE dst=? AND kind='supersedes' AND src>? ORDER BY src",
        (nid,nid))]

def verdict(term):
    db=_conn(); c=db.cursor()
    q=term.replace('"',' ')
    rows=c.execute("SELECT rowid FROM ft WHERE ft MATCH ? ORDER BY rowid DESC",(q,)).fetchall()
    ids=[r[0] for r in rows]
    if not ids:
        hits=c.execute("SELECT DISTINCT note FROM ents WHERE val=? ORDER BY note DESC",
                       (term.lower(),)).fetchall()
        ids=[h[0] for h in hits]
    if not ids: print("no notes match %r"%term); return
    live,dead=[],[]
    for nid in ids:
        sup=superseded_by(c,nid)
        (dead if sup else live).append((nid,sup))
    print("=== CURRENT (newest first) ===")
    for nid,_ in live[:8]:
        t,d,st=c.execute("SELECT title,date,status FROM notes WHERE id=?", (nid,)).fetchone()
        print("  notes/%-3d [%-9s] %s  %s"%(nid,st,d,t[:78]))
    if dead:
        print("\n=== SUPERSEDED -- do not quote these as current ===")
        for nid,sup in dead[:8]:
            t,d,st=c.execute("SELECT title,date,status FROM notes WHERE id=?", (nid,)).fetchone()
            print("  notes/%-3d [%-9s] %s  %s"%(nid,st,d,t[:64]))
            print("            ^ overturned by %s"%", ".join("notes/%d"%s for s in sup))

def addr(a):
    a=a.lower()
    if not a.startswith('0x'): a='0x'+a
    a='0x'+a[2:].lstrip('0').zfill(4)
    db=_conn(); c=db.cursor()
    # DISTINCT: normalisation maps "2b80a8" and "02b80a8" to the same value, so a note
    # spelling an address both ways joined twice and printed twice.
    rows=c.execute("""SELECT DISTINCT n.id,n.status,n.date,n.title FROM ents e
                      JOIN notes n ON n.id=e.note WHERE e.val=? ORDER BY n.id DESC""",(a,)).fetchall()
    if not rows: print("no notes mention %s"%a); return
    print("notes touching %s:"%a)
    for nid,st,d,t in rows:
        sup=superseded_by(c,nid)
        mark=("  <-- SUPERSEDED by "+", ".join("notes/%d"%s for s in sup)) if sup else ""
        print("  notes/%-3d [%-9s] %s  %s%s"%(nid,st,d,t[:66],mark))

def show(nid):
    db=_conn(); c=db.cursor()
    r=c.execute("SELECT title,date,status,path FROM notes WHERE id=?", (int(nid),)).fetchone()
    if not r: sys.exit("no notes/%s"%nid)
    t,d,st,p=r
    print("notes/%s  [%s]  %s\n  %s\n  %s"%(nid,st,d,t,p))
    sup=superseded_by(c,int(nid))
    if sup: print("  ** SUPERSEDED BY: %s **"%", ".join("notes/%d"%s for s in sup))
    ov=c.execute("SELECT dst,context FROM refs WHERE src=? AND kind='supersedes'",(int(nid),)).fetchall()
    for dst,ctx in ov: print("  overturns notes/%d: ...%s..."%(dst,ctx[:150]))

def stale():
    db=_conn(); c=db.cursor()
    print("notes overturned by a LATER note (quote the superseding one instead):")
    # MATERIALISE first: superseded_by() runs on this same cursor, and executing on a
    # cursor mid-iteration RESETS it -- so the loop ended after one row and stale()
    # printed an empty list while 26 edges sat in the table.  A tool that reports
    # "nothing found" without ever looking is the failure mode this whole index exists
    # to prevent, so: never iterate a cursor you also query inside the loop.
    ids=[r[0] for r in c.execute("SELECT id FROM notes ORDER BY id").fetchall()]
    for nid in ids:
        sup=superseded_by(c,nid)
        if sup:
            t=c.execute("SELECT title FROM notes WHERE id=?", (nid,)).fetchone()[0]
            print("  notes/%-3d -> %s   %s"%(nid,", ".join("notes/%d"%s for s in sup),t[:60]))

if __name__=='__main__':
    a=sys.argv[1:] or ['--help']
    if   a[0]=='build':   build()
    elif a[0]=='verdict': verdict(' '.join(a[1:]))
    elif a[0]=='addr':    addr(a[1])
    elif a[0]=='show':    show(a[1])
    elif a[0]=='stale':   stale()
    else: print(__doc__)
