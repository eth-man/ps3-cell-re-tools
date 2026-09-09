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
    python3 tools/notedb.py tagaudit         # notes whose [tag] contradicts their title

A note that is ABOUT the record (an audit, a frontier page) must carry the marker
    <!-- notedb: no-supersede -->
or it will appear to supersede every note it quotes.

A note whose retraction is scoped to ONE SECTION should declare its real status:
    <!-- notedb: status=corrected -->
otherwise a "### 4. RETRACTED ..." heading marks the WHOLE note retracted.
    python3 tools/notedb.py selftest         # regression test for the status classifier
"""
import sys, os, re, sqlite3, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTES = os.path.join(ROOT, 'notes')
DB    = os.path.join(ROOT, 'data', 'notes.db')
# RULE 1 step 1 searches notes/ AND the memory directory; the index used to cover only notes/.
# So `notedb addr` answered confidently about strictly less than the rule requires -- 360
# addresses live ONLY in memory files, including silicon results (`loader-re`, notes/816:
# `0x2fecdc` was measured from a crash log into project_ps3_createload_session six days before
# it was re-derived statically).  Same defect class as the three ADDR form-blindnesses: a search
# that answers confidently about less than the caller assumes.
MEMDIR = os.path.expanduser('~/.claude/projects/-opt-projects-ps3/memory')

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
# A note can supersede ITSELF. notes/117 opens with "878 ... left untried" and then, further
# down under its own later date, records "Final: 878 tested." Per-note status has no way to
# express that, so two later notes (231, 239) quoted the stale half. Flag any note whose BODY
# carries a date later than its header date: it is a multi-episode note and must be read to
# the end before being quoted.
H1_RE = re.compile(r'^# (\S.*)$', re.M)
def sections(text):
    """Top-level headings. A note with more than one has EPISODES, and a later episode
    can supersede the earlier text -- notes/117 opens with '878 ... left untried' and
    later records 'Final: 878 tested'. A date heuristic misses it (same day), so key on
    structure. Most notes here are multi-section, so this is surfaced per-note in `show`
    rather than as a global warning."""
    return H1_RE.findall(text)

# '>' is allowed before the '#': notes/720 opens with a blockquoted banner,
# '> # RETRACTED IN FULL -- Both of this note's claims are wrong. Do not cite this
# note for anything.'  Without the '>' the heading scanner saw NO retraction heading,
# so notes/720 indexed as [closed] and its six supersession edges stayed live -- which
# is how notes/236 ('THE MODULE'S DMA DELIVERS') and notes/237 ('THE OVERFLOW FIRED ON
# SILICON') came to be printed under 'SUPERSEDED -- do not quote these as current' on
# the authority of a note that retracts itself in full.
RETRACT_HEAD = re.compile(r'^\s*>?\s*#{1,4}.*\bRETRACT\w*.*$', re.I|re.M)

def _retracts_other(head, own):
    """True if this heading retracts a DIFFERENT note. The note number must be the
    grammatical OBJECT of the retraction -- 'RETRACTION of notes/223', 'RETRACTS
    notes/211', 'retracts a reading from notes/312', "notes/213's explanation
    retracted". A bare pointer ('RETRACTED -- see notes/113', notes/112) is NOT an
    other-retraction, and a note's OWN number never counts (notes/142's title is
    'notes/142 -- RETRACTED: ...', which is a SELF-retraction)."""
    if re.match(r'^\s*#{1,4}\s*Retractions?\s*$', head, re.I):
        return True                                   # bare "## Retractions" list section
    # DIRECTION (2026-09-05): "RETRACTED BY notes/471" is the PASSIVE -- this note is the
    # one being retracted, by that note. It is the opposite of "RETRACTION OF notes/471".
    # Without this, notes/469 ("[RESULT 3 RETRACTED by notes/471]") read as retracting
    # someone else and lost its own retracted status -- exactly the case the index exists
    # to surface.
    if re.search(r'\bretract\w*\s+by\s+notes?/\d+', head, re.I):
        return False
    pats = (r'retract\w*\s+(?:of\s+|from\s+)?notes?/(\d+)',
            r'retract\w*[^.\n]{0,30}?\bfrom\s+notes?/(\d+)',
            r'notes?/(\d+)[^.\n]{0,50}?\bretract',
            # 2026-09-05: this corpus most often writes the object after a SEPARATOR, not
            # after "of" -- "RETRACTION: notes/217", "RETRACTION - notes/469's",
            # "RETRACTION FIRST - notes/386".  Without these, notes/205/218/310/387/471 --
            # all of which retract SOMEONE ELSE in a label-position heading -- were
            # classified as self-retracted.  A bare pointer ("RETRACTED -- see notes/113")
            # still must NOT count, so "see" is excluded explicitly.
            r'retract\w*\s*(?:\w+\s*)?[:\u2014\u2013-]+\s*(?!see\b)(?:of\s+|from\s+)?notes?/(\d+)')
    for pat in pats:
        for m in re.finditer(pat, head, re.I):
            if own is None or int(m.group(1)) != own:
                return True
    return False

_QUOTED = re.compile(r'"[^"]*"|`[^`]*`|\u201c[^\u201d]*\u201d')

# Strip a heading's structural prefix: leading '#'s, then numbering like "2." / "s2" /
# "s2 —" / "3.1", so we can ask WHERE in the actual sentence the word falls.
# Strips, in order: leading '#'s; this corpus's "notes/NNN -" title prefix; section
# numbering ("2." / "s2" / "3.1"); and a trailing separator.  The notes/NNN part matters:
# without it "# notes/469 - [RESULT 3 RETRACTED by ...]" put RETRACT at column 24 and the
# label test missed a genuine self-retraction.
_HEAD_PREFIX = re.compile(r'^\s*>?\s*#{1,6}\s*(?:notes?/\d+\s*[-\u2014:]?\s*)?'
                          r'(?:[sS]?\d+(?:\.\d+)*\.?)?\s*(?:[-\u2014:]\s*)?')
# (An earlier version also tried to strip a leading "[...]" token. Its `[^\]]{0,20}` ate
#  20 chars INSIDE the bracket and swallowed the keyword -- "# notes/469 - [RESULT 3
#  RETRACTED by ...]" became "y notes/471]...". Bracketed prefixes are left alone.)

def _self_retracted(text, own=None):
    # A heading that only QUOTES the word (notes/346's title is
    # 'notedb labelled every CORRECTION note "retracted"') is talking ABOUT
    # retraction, not performing one -- strip quoted spans before deciding.
    #
    # AND (2026-09-05, notes/568): the word must be used as a LABEL, not in passing.
    #   self-retraction : "## s2 - RETRACTED: the module-pointer FORM is NOT the cause"
    #   passing mention : "## 2. This restores the SLB cause ... than the one that was retracted"
    # Both contain RETRACT and neither names a note number, so _retracts_other cannot
    # separate them. A real self-retraction announces itself at the START of the heading;
    # a discussion mentions it mid-sentence. Require the match within the first 20 chars
    # of the heading text once the '#'/numbering prefix is removed.
    # PER-HEADING (2026-09-05): the first attempt at this filtered the heading list first
    # and then asked "does ANY of them retract another note?".  That REGRESSED five notes
    # (205/218/310/387/471): their exculpating "RETRACTION of notes/X" heading was dropped
    # by the label-position filter, leaving only a label-position heading behind, so they
    # flipped to self-retracted.  A note is self-retracted iff SOME SINGLE heading is both
    # label-position AND not aimed at another note.
    # Two conditions, and BOTH scopes matter (2026-09-05):
    #   (a) SOME heading must use the word as a LABEL (at the start, after '#'/numbering) --
    #       a passing mention like "## 2. ... than the one that was retracted" is discussion,
    #       not a retraction  (this was notes/568's false positive);
    #   (b) NO heading anywhere in the note may name ANOTHER note as the object -- a note
    #       often announces "## 1. RETRACTION: ..." in a section while naming its target
    #       only in the title (notes/205 retracts notes/179 that way, notes/310 notes/311).
    # Per-heading-only fails (a)+(b) together; global-only fails (a). Both are required.
    heads = RETRACT_HEAD.findall(text)
    has_label = False
    for h in heads:
        body = _HEAD_PREFIX.sub('', _QUOTED.sub('', h))
        m = re.search(r'\bRETRACT\w*', body, re.I)
        if m and m.start() <= 20:
            has_label = True
            break
    if not has_label:
        return False
    return not any(_retracts_other(h, own) for h in heads)

def title_of(text):
    """The note's title: first line that is neither blank nor an HTML comment, with a leading
    '#' / 'notes/N -' / '**' pair stripped.  Factored out of build() so status_of() can see it."""
    head = ""
    for ln in text.split('\n'):
        t = ln.strip()
        if not t or (t.startswith('<!--') and t.endswith('-->')):
            continue
        head = ln
        break
    title = re.sub(r'^#+\s*', '', head)
    title = re.sub(r'^notes?/\d+\s*[-—:]*\s*', '', title)
    if title.startswith('**'):
        title = title[2:]
        title = title.replace('**', '', 1)
    return title.strip()

def _scoped_only(text):
    """True when every retraction heading is a SUBSECTION (##+) rather than the note's own
    H1/banner.  RULE 3 says "retract in place", and this corpus does partial self-retraction
    constantly -- 27 of 43 notes classified [retracted] on 2026-09-06 were marked so by a
    single '## RETRACTION: ...' inside an otherwise standing note, and `verdict` then filed
    them under "SELF-RETRACTED -- the note withdrew its own claims", which is false for all 27.
    notes/777 is the clearest: it found a regex bug in eight tools and retracted ONE sub-claim
    about `selftest_verify.py`; the sweep stands.

    This deliberately does NOT touch `_self_retracted` -- that answers "does this note retract
    ITSELF rather than another note", and for notes/529 the answer is genuinely yes.  What was
    wrong is the STATUS it mapped to.  So the SELFTEST expectations are untouched, and the
    explicit `<!-- notedb: status=... -->` override still wins over both.
    """
    heads = RETRACT_HEAD.findall(text)
    if not heads:
        return False
    return not any(re.match(r'^\s*>?\s*#\s', h) for h in heads)

STATUS_PATTERNS = [
    # SELF-retraction only.  v1 matched ANY heading containing RETRACT, which labelled
    # every note that CORRECTS ANOTHER NOTE as itself retracted -- notes/205,214,218,220,
    # 224,230,244,257,310,313,345 are all corrections, i.e. the most authoritative notes
    # in the corpus, and the hook was injecting "[retracted]" for them into every prompt.
    # A note number appearing as the OBJECT of the retraction ("RETRACTION of notes/223",
    # "RETRACTS notes/211", "notes/213's explanation retracted"), or a bare plural
    # "Retractions" list section, means it is retracting SOMEONE ELSE.
    ('retracted',  lambda t,o=None: _self_retracted(t,o) and not _scoped_only(t)),
    # A self-retraction confined to ONE SECTION is a CORRECTION, not a withdrawal.
    ('corrected',  lambda t,o=None: _self_retracted(t,o) and _scoped_only(t)),
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
    # A body keyword must NOT override an explicitly positive TITLE.  The pattern below scans
    # the WHOLE BODY, so a single "does not" -- including in a sentence REVERSING a negative,
    # which is literally what notes/236 says ("it reverses the load-bearing negative") -- outranked
    # the headline.  notes/237 "THE OVERFLOW FIRED ON SILICON" and notes/238 "CONTROL PASSED" were
    # both filed [negative]: 30 notes whose tag contradicted their own title, and the second time
    # in one day that this corpus's flagship silicon results were mislabelled by the index
    # (notes/731 §2 was the first).  Narrow by construction -- it fires only where `tagaudit`
    # already reported a conflict, i.e. the title asserts a positive AND carries no negation.
    ('negative',   lambda t,o=None: (not _tag_conflict('negative', title_of(t)))
                                    and bool(re.search(r'\bhonest negative\b|\bdoes NOT\b|'
                                                       r'\bNEGATIVE\b', t, re.I))),
    ('open',       re.compile(r'\bOPEN, not closed\b|\bstill OPEN\b|\bUNRESOLVED\b', re.I)),
]
# A note declaring its OWN supersession and naming the LATER note that did it:
# "RETRACTED by notes/484", "SUPERSEDED 2026-09-06 by the parallel session, notes/655".
# The classifier in build() only reads the SUPERSEDING note, so a retraction announced in
# the note BEING retracted produced no edge at all.  Twelve real links were missing for
# this reason alone (478<-484, 479<-481, 480<-481, 483<-484, 606<-607, 627/628/629<-655,
# 632<-637, 663<-664, 663<-667, 718<-719) while eleven others -- the control that this
# detector returns positives as well as negatives -- were already covered from the other end.
PASSIVE_SELF = re.compile(r'\b(RETRACT\w*|SUPERSEDED|CORRECTED|REFUTED|OVERTURNED|'
                          r'WITHDRAWN)\b[^.\n]{0,60}?\bby\b[^.\n]{0,40}?notes?/(\d{1,4})', re.I)

# Edges the classifier creates that a HUMAN READING OF THE SENTENCE shows to be wrong.
# These are removals, and a removal needs per-edge evidence -- a heuristic that silently
# dropped 27 edges to gain 17 was tried first and rejected, because "passes clean" without
# a checked control is this project's most expensive failure mode (RULE 3).  Each entry
# quotes the sentence that settles the direction.  Anything not listed here stays.
FALSE_EDGES = {
 (474,473): 'notes/474: "notes/465 (...) is refuted by notes/473" -- 473 is the AGENT; '
            'the real edge is 473->465, which is already recorded.',
 (667,500): 'notes/667 s2 is titled "notes/500 is VINDICATED"; the stray verb is in the '
            'previous sentence ("overturned by cause, not by vote."). 667 RESTORES 500. '
            'What 667 does retract is notes/663 s1, and that edge is created by PASSIVE_SELF.',
 (700,655): 'notes/700 line 12: "SUPERSEDED 2026-09-06 by the parallel session, '
            'notes/655-659." 655-659 supersede 700, not the reverse. Note numbering is NOT '
            'time order across the 675/700 boundary: 700+ is a concurrent session.',
 (701,655): 'notes/701 line 1: same sentence, same direction. 655-659 supersede 701.',
 (720,236): 'notes/720\'s retraction banner QUOTES notedb output ("^ overturned by '
            'notes/236, notes/237"). The verb is the tool\'s, not the note\'s.',
 (720,237): 'same quoted banner, and separately notes/720 quotes notes/236\'s words '
            '(*"RETRACTS notes/226 PART 7"*) -- that retraction is 236\'s, not 720\'s.',
 (720,226): 'as above: the RETRACTS belongs to the quoted notes/236, which already carries '
            'its own 236->226 edge.',
 (720,436): 'notes/720: "should be treated as superseded with the rest, per notes/436" -- '
            '720 is saying IT is superseded per 436, the opposite of the recorded edge.',
 (222,179): 'notes/222 title: "notes/179\'s conclusion was right." 222 CONFIRMS 179.',
 (675,205): "notes/675 lines 9-14 QUOTE `notedb verdict 0xa70` output verbatim, including "
            "the line 'notes/179 [corrected]  SUPERSEDED BY notes/205, 207, 211, 212, 222'. "
            "The verb is the TOOL's, not notes/675's -- the same shape as notes/720. This was "
            "the ONLY superseder of notes/205 ('the saved-LR smash IS real'), so a note quoting "
            "the index was striking out a result the index had just been repaired to protect.",
 (676,411): "notes/676 s1 quotes `notedb show 402`'s own header ('** SUPERSEDED BY: notes/411 **') "
            "while describing the error of NOT running the tool. The verb is the tool's. "
            "notes/411 keeps its real superseders, notes/412 and notes/416.",
 (414,406): "notes/414 line 15: 'that conclusion is superseded by the working chain of "
            "notes/406-413' -- the subject is NOTES/230's conclusion and notes/406-413 is the "
            "AGENT. notes/414 does not overturn notes/406; it is built on it.",
 (459,197): "notes/459 line 50 BLOCKQUOTES `project_ps3_current_frontier`: 'REFUTED 2026-09-02 "
            "(notes/197): ...'. notes/197 is the SOURCE of that refutation, not its object. "
            "notes/459 goes on to rely on notes/197's warning.",
 (456,197): "notes/456 heading: 'Why it is closed (authoritative, notes/196 + notes/197)', and "
            "line 24 calls notes/197's finding 'the strongest possible form of a negative'. "
            "It cites notes/197 approvingly. With this and 459 removed notes/197 has no "
            "superseders, which is correct: both notes rest ON it.",
 (665,500): "notes/665 s4 is headed \"Why notes/500 SUCCEEDED and we did not\" -- it explains "
            "notes/500, it does not overturn it (notes/667 s1 then reproduces notes/500 to the "
            "digit). The verb is the previous section's closing sentence, 'a *post-success* "
            "signalling failure. Retracted.', which the 60-char window reaches back across a "
            "sentence end AND a heading boundary to grab. Ruled by the `silicon` session, "
            "notes/734; the annotation at line 96 produces no edge (it names notes/666, which "
            "is later, so the append-only rule already drops it).",
 (432,402): 'notes/432: "...was wrong, and is retracted here." is a complete sentence about '
            'something else; "Also worth restating: notes/402\'s ..." is the next one.',
}
# Edges the record states plainly but no pattern can derive, for the same reason: they run
# BACKWARDS along the note numbering.  notes/700-709 were written by a session running
# CONCURRENTLY with notes/655-675, so for that block a higher number is not a later note and
# the append-only assumption above ("a note can only overturn an EARLIER one") is false.
TRUE_EDGES = {
 (655,700): 'notes/700 line 12: "SUPERSEDED 2026-09-06 by the parallel session, '
            'notes/655-659." Recorded against 655, the first note of the range it names.',
 (655,701): 'notes/701 line 1: same declaration, same range.',
}
# Addresses.  Two shapes, because the corpus has two address spaces:
#   * 5-8 hex digits, 0x optional -- PPE/lv1/lv2 (0x2b80a8, 2f9738).  Bare digits are safe
#     at this width; at narrower widths they collide with ordinary numbers and dates.
#   * 3-4 hex digits, 0x REQUIRED -- SPU local store and stop codes (0xa70, 0x988, 0x2101,
#     0x3e000 is 5 so it is already covered).  These were UNINDEXED entirely: ADDR demanded
#     five digits, so `notedb addr 0xa70` printed a confident two-note answer while 0xa70
#     appears in 145 places across the corpus -- the whole sv_iso/isolation vocabulary was
#     invisible to the tool whose stated purpose is "hex addresses are the stable join key".
#     1-2 digit values (0x10, 0x20, 0xff) stay out: those are offsets and flags, not addresses.
# A note that is ABOUT the record rather than about the console -- an audit, a frontier
# page, a reconciliation -- quotes every note it discusses, retraction verbs and all, and so
# appears to supersede all of them.  This module's own header records the first instance
# ("tonight's own write-up ... appeared to supersede all of them"); notes/730 and notes/731
# reproduced it immediately on being written, marking notes/236 and notes/237 superseded for
# the second time in one day.  Such a note declares itself with this marker on any line and
# then contributes NO supersession edges in either direction.
NO_SUPERSEDE = re.compile(r'<!--\s*notedb:\s*no-supersede\s*-->', re.I)

# An AUTHOR-DECLARED status, overriding the keyword classifier:  <!-- notedb: status=corrected -->
# WHY (2026-09-06, `sdk-work`): RULE 3 says "retract in place", and this corpus does PARTIAL
# retractions constantly -- notes/713 retracts notes/712 s1, notes/718 s3b, notes/736 closes
# notes/733 s4.  When such a retraction is SELF-scoped, the heading names no other note, so
# `_self_retracted` sees a label-position RETRACT with no object and marks the WHOLE note
# retracted.  notes/732 lost its entire still-valid survey that way to a
# "### 4. RETRACTED IN PLACE" heading.  The project's documented practice and the tool's model
# genuinely disagree, and the failure is silent: the note indexes, `build` succeeds, the status
# is simply wrong.
#
# Deliberately NOT inferred from formatting.  The obvious heuristic -- "a section-numbered
# heading scopes its retraction to that section" -- would reclassify notes/529
# ("## s2 - RETRACTED: ...", a SELFTEST case expecting self-retracted) and notes/551, so
# adopting it means overruling recorded expectations on a guess.  An explicit marker costs the
# author six words, involves no judgement, and states the scope where humans read it too.
STATUS_OVERRIDE = re.compile(r'<!--\s*notedb:\s*status\s*=\s*([a-z]+)\s*-->', re.I)
VALID_STATUS = ('retracted','corrected','closed','negative','open','info')
ADDR  = re.compile(r'\b(?:0x)?([0-9a-f]{5,8})\b', re.I)
ADDR2 = re.compile(r'\b0x([0-9a-f]{3,4})\b', re.I)
# 9-16 digits, 0x optional -- the 64-bit space: lv1 real addresses (0x4c0001000000),
# LPAR/tagged EAs (0x1000000000300000), authority ids (0x1070000002000001), the BE MMIO
# base (0x20000000000), loader version words (0x0004009300000000).
# WHY (2026-09-06, `cell-env`): the widening above was done DOWNWARD only.  ADDR's upper
# bound of 8 left 708 distinct addresses across 357 of 740 notes unindexed -- nearly half
# the corpus, and the most-cited constants in it: the LAID appears in 35 notes and
# `notedb addr 0x1070000002000001` answered "no notes mention" for every one of them.
# Same failure as the 3-4 digit case recorded above, same false-zero shape, opposite end.
# `\b` on both sides keeps this off substrings of long hashes (a 64-char digest has no
# word boundary at 16), so sha256s do not flood the index.
ADDR3 = re.compile(r'\b(?:0x)?([0-9a-f]{9,16})\b', re.I)
# DECOMPILER-NAMED functions.  `decomp/` is Ghidra output, so anything decompiler-derived is
# named `FUN_0031588c` in the notes -- and RULE 1 step 1 says grep the ARTIFACT, which for a
# decompiled function is exactly this form.  `notedb addr 0x31588c` answered "no notes mention"
# while notes/157, /158, /162 and /164 discuss that function at length; notes/158 documents its
# first gate.  Measured: FUN_00xxxxxx = 133 distinct across 62 notes, 30 invisible; FUN_ without
# the 00 prefix = 27 distinct, 18 invisible.  Only *some* were invisible because the rest happen
# to also appear in 0x form somewhere -- silent and PARTIAL, which is the worst shape: the tool
# answers correctly often enough to be trusted.  (`loader-re`, found by hitting it mid-trace.)
# sub_/loc_ are unused in this corpus today and cost nothing to accept; this is the third
# form-blindness in ADDR in one day (digit floor, digit ceiling, naming convention).
ADDR4 = re.compile(r'\b(?:FUN|LAB|sub|loc)_([0-9a-f]{4,16})\b', re.I)
# 1-4 digits.  At 3 it SILENTLY dropped any note numbered 1000+: the file was globbed,
# the regex failed to match, and the note simply never entered the index -- no warning, the
# same invisible-note failure that cost notes/739 its visibility today, but permanent and for
# a whole lane.  This matters because the per-lane range scheme under discussion puts one lane
# at 1000+.  Verified with a control: notes/1000 was created, `build` reported success, and
# `SELECT ... WHERE id=1000` returned None.
NREF = re.compile(r'notes?/(\d{1,4})')

def note_files():
    """(id, path) for every numbered note.  DUPLICATE NUMBERS: several sessions write notes
    concurrently and two of them can claim the same number -- on 2026-09-06 notes/732 was
    taken twice, four minutes apart, and `build` died with a bare
    `sqlite3.IntegrityError: UNIQUE constraint failed: notes.id`.  Because build is atomic
    the old index survived, but NO session could reindex until a human renamed a file, and
    the traceback did not say which files collided.  Now: keep the EARLIER-created file (it
    claimed the number first), report the collision loudly, and still produce an index -- a
    flagged index beats no index.  `build` exits non-zero so it cannot pass unnoticed."""
    by_id={}
    for p in sorted(glob.glob(os.path.join(NOTES,'*.md'))):
        m=re.match(r'(\d{1,4})-', os.path.basename(p))
        if m: by_id.setdefault(int(m.group(1)),[]).append(p)
    global DUPES
    DUPES=[]
    out=[]
    for nid,paths in sorted(by_id.items()):
        if len(paths)>1:
            paths=sorted(paths, key=lambda q: os.stat(q).st_mtime)
            DUPES.append((nid,paths))
        out.append((nid,paths[0]))
    return out
DUPES=[]
BADSTATUS=[]

def status_of(text, own=None):
    m = STATUS_OVERRIDE.search(text)               # the author's own declaration wins
    if m and m.group(1).lower() in VALID_STATUS:
        return m.group(1).lower()
    for name,pat in STATUS_PATTERNS:
        hit = pat(text, own) if callable(pat) else bool(pat.search(text))
        if hit: return name
    return 'info'

def build():
    # ATOMIC.  v1 removed the live DB and then repopulated it over several seconds.  This
    # project runs several sessions at once (`silicon`, `loader-re`, `sdk-work`, `record`),
    # so during every rebuild the others' queries hit an empty or half-filled index -- and
    # the staleness warning added above then screams "731 unindexed" at them.  Two builds
    # racing also killed one outright ("sqlite3.OperationalError: disk I/O error", 2026-09-06)
    # because one process removed the file the other held open.  Build into a private temp
    # file and os.replace() it in: readers see either the whole old index or the whole new one.
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    tmp = "%s.build-%d" % (DB, os.getpid())
    if os.path.exists(tmp): os.remove(tmp)
    db=sqlite3.connect(tmp); c=db.cursor()
    c.executescript("""
    CREATE TABLE notes(id INTEGER PRIMARY KEY, title TEXT, date TEXT, path TEXT,
                       status TEXT, body TEXT);
    CREATE TABLE refs(src INTEGER, dst INTEGER, kind TEXT, context TEXT);
    CREATE TABLE ents(note INTEGER, kind TEXT, val TEXT);
    CREATE INDEX ents_val ON ents(val);
    CREATE INDEX refs_dst ON refs(dst, kind);
    CREATE VIRTUAL TABLE ft USING fts5(title, body, content='');
    CREATE TABLE mem(path TEXT, val TEXT);
    CREATE INDEX mem_val ON mem(val);
    """)
    back=[]                                       # passive self-declared supersessions
    global BADSTATUS
    BADSTATUS=[]
    for nid, path in note_files():
        text=open(path, errors='replace').read()
        # TITLE: see title_of().  Skips HTML comments (the `no-supersede` marker is routinely
        # written on line 1, and taking line 1 verbatim titled 24 notes with the marker itself).
        title = title_of(text)
        # DATE: prefer a date on a line the NOTE wrote, not one a later banner added.
        # Banners are blockquoted (`> **PARTIAL CORRECTION -- 2026-09-06 ...**`) and get
        # prepended above the original `Date:` line, so scanning text[:400] blindly re-dates
        # the note to the correction.  Demonstrated on notes/117 (2026-08-27 -> 2026-09-06)
        # and caught before it stuck; corpus-wide instances today: 0.  A misdated note reads
        # perfectly and its provenance is simply a lie -- RULE 1d, at the level of the index.
        date=''
        for _ln in text[:2000].split('\n'):
            if _ln.lstrip().startswith(('>','<!--')):
                continue
            _m=re.search(r'(?:Date:\s*)?(20\d\d-\d\d-\d\d)', _ln)
            if _m:
                date=_m.group(1); break
        if not date:
            _m=re.search(r'(?:Date:\s*)?(20\d\d-\d\d-\d\d)', text[:400])
            date=_m.group(1) if _m else ''
        mo = STATUS_OVERRIDE.search(text)
        if mo and mo.group(1).lower() not in VALID_STATUS:
            BADSTATUS.append((nid, mo.group(1)))
        c.execute("INSERT INTO notes VALUES(?,?,?,?,?,?)",
                  (nid,title,date,os.path.relpath(path,ROOT),status_of(text,nid),text))
        c.execute("INSERT INTO ft(rowid,title,body) VALUES(?,?,?)",(nid,title,text))
        # entities: hex addresses are the stable join key across vocabulary drift
        _hits = set()
        for _rx in (ADDR, ADDR2, ADDR3, ADDR4):
            _hits |= set(x.lower() for x in _rx.findall(text))
        for a in _hits:
            c.execute("INSERT INTO ents VALUES(?,?,?)",(nid,'addr','0x'+a.lstrip('0').zfill(4)))
        # cross references, classified by the words IMMEDIATELY BEFORE them.
        # Deduped per (src,dst,kind): a note citing another twenty times is one edge, and
        # v1's duplicates made "SUPERSEDED by notes/185, notes/185, notes/185" output.
        seen=set()
        meta = bool(NO_SUPERSEDE.search(text))   # record-keeping note: asserts no supersession
        # A note that announces its OWN supersession -- "RETRACTED by notes/484",
        # "SUPERSEDED 2026-09-06 by ... notes/655" -- states the edge in the note being
        # overturned, where the classifier below never looks (it only reads the SUPERSEDING
        # note).  Twelve real links were absent for this reason alone: 478<-484, 479<-481,
        # 480<-481, 483<-484, 606<-607, 627/628/629<-655, 632<-637, 663<-664, 663<-667,
        # 718<-719.  The superseder must be a LATER note; the log is append-only.
        for m in PASSIVE_SELF.finditer(text):
            src=int(m.group(2))
            if src<=nid or meta: continue
            key=('P',src)
            if key in seen: continue
            seen.add(key)
            back.append((src,nid,m.group(0).replace('\n',' ').strip()[:300]))
        last_verb=None                                # for enumerated retraction lists
        for mm in NREF.finditer(text):
            dst=int(mm.group(1))
            if dst==nid: continue
            pre=text[max(0,mm.start()-60):mm.start()]
            prev=NREF.search(pre)
            if prev:                                  # another ref sits between verb and us
                pre=pre[prev.end():]
            # a verb sealed inside a parenthetical that CLOSES before the reference is
            # describing something else ("(... ABI correct)  notes/206") -- drop it.
            if ')' in pre:
                pre=pre[pre.rindex(')')+1:]
            v=OVERTURN.search(pre)
            # ENUMERATED LIST.  "Corrects notes/321, notes/338, notes/339, notes/340" gives
            # the verb only to the FIRST item, because the text from the previous reference
            # to this one is just a separator.  14 edges were lost this way (notes/238, /240,
            # /341, /431, /568, /577, /609, /631, /670, /82 ...).  Carry the verb across a
            # segment that is nothing but list punctuation and a short parenthetical gloss.
            if v is None and last_verb is not None and prev and \
               re.fullmatch(r"[\s,;+/&`'\"*_-]*(?:and|plus|s\d+|\([^)]{0,40}\)|"
                            r"[a-z]{0,12})[\s,;+/&`'\"*_-]*", pre, re.I):
                v=last_verb
            kind='supersedes' if (v is not None and not meta) else 'cites'
            last_verb=v if kind=='supersedes' else None
            # a note can only overturn an EARLIER one; the log is append-only
            if kind=='supersedes' and dst>=nid: kind='cites'
            # ...except where reading the sentence shows the direction is wrong; see
            # FALSE_EDGES.  Removals are listed one by one WITH the quoted sentence rather
            # than inferred by pattern, so every deletion is auditable and reversible.
            if kind=='supersedes' and (nid,dst) in FALSE_EDGES: kind='cites'
            key=(dst,kind)
            if key in seen: continue
            seen.add(key)
            ctx=text[max(0,mm.start()-160):mm.end()+160].replace('\n',' ')
            c.execute("INSERT INTO refs VALUES(?,?,?,?)",(nid,dst,kind,ctx.strip()[:300]))
    metas={nid for nid,pp in note_files()
           if NO_SUPERSEDE.search(open(pp,errors='replace').read())}
    c.execute("DELETE FROM refs WHERE kind='supersedes' AND (src IN (%s) OR dst IN (%s))"
              %(','.join(map(str,metas)) or '-1', ','.join(map(str,metas)) or '-1'))
    for mp in sorted(glob.glob(os.path.join(MEMDIR,'*.md'))):
        try: mt=open(mp,errors='replace').read()
        except OSError: continue
        _mh=set()
        for _rx in (ADDR, ADDR2, ADDR3, ADDR4):
            _mh |= set(x.lower() for x in _rx.findall(mt))
        for a in _mh:
            c.execute("INSERT INTO mem VALUES(?,?)",
                      (os.path.basename(mp),'0x'+a.lstrip('0').zfill(4)))
    for (src,dst),why in TRUE_EDGES.items():
        back.append((src,dst,why))
    for src,dst,ctx in back:
        if not c.execute("SELECT 1 FROM refs WHERE src=? AND dst=? AND kind='supersedes'",
                         (src,dst)).fetchone():
            c.execute("INSERT INTO refs VALUES(?,?,?,?)",(src,dst,'supersedes',ctx))
    db.commit()
    n=c.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    s=c.execute("SELECT COUNT(*) FROM refs WHERE kind='supersedes'").fetchone()[0]
    # NEW EDGES SINCE THE LAST BUILD.  A spurious supersession is SILENT to the note that
    # causes it and LOUD to the note that suffers it: nothing tells an author that the note
    # they just wrote has marked someone else's measurement "do not quote as current", while
    # every session's recall banner starts saying so.  notes/738 marked notes/125 -- the
    # metldr container coverage measurement its own argument RESTS ON -- and `loader-re` only
    # noticed because the banner happened to surface in their context.  So say it at the
    # moment of creation, to the person who can still fix it.  (`loader-re`'s suggestion.)
    fresh=[]
    try:
        old=sqlite3.connect('file:%s?mode=ro'%DB, uri=True)
        prev=set(old.execute("SELECT src,dst FROM refs WHERE kind='supersedes'"))
        old.close()
        now=set(c.execute("SELECT src,dst FROM refs WHERE kind='supersedes'"))
        fresh=[(a,b,(c.execute("SELECT title FROM notes WHERE id=?",(b,)).fetchone() or [''])[0])
               for a,b in sorted(now-prev)]
    except Exception:
        pass                                       # first build: nothing to diff against
    # META-NOTE SMELL.  A note that suddenly overturns a large number of others is almost
    # always an audit/frontier/ruling that QUOTES them rather than a result that overturns
    # them -- notes/720 (6 edges), then notes/730, notes/731 and notes/734 each did it within
    # a day, two of them written by sessions that did not know the marker existed. Warn; the
    # author decides. Genuine multi-note retractions exist (notes/238 retracts 6 by name).
    heavy=[r for r in c.execute("SELECT src,COUNT(*) c FROM refs WHERE kind='supersedes' "
                                "GROUP BY src HAVING c>=5 ORDER BY c DESC").fetchall()]
    if heavy:
        sys.stderr.write("\n*** notes that overturn 5+ others -- if any is an audit/frontier/\n"
                         "    ruling ABOUT the record, add '<!-- notedb: no-supersede -->' under\n"
                         "    its title or it will mark everything it quotes as superseded:\n")
        for src,cnt in heavy:
            t=c.execute("SELECT title FROM notes WHERE id=?", (src,)).fetchone()[0]
            sys.stderr.write("      notes/%-4d overturns %2d   %s\n"%(src,cnt,t[:62]))
    db.close()
    os.replace(tmp, DB)                           # atomic swap; readers never see a partial DB
    print("indexed %d notes, %d supersession edges -> %s"%(n,s,os.path.relpath(DB,ROOT)))
    if fresh:
        sys.stderr.write("\n*** NEW supersession edges this build -- each one makes the RIGHT-hand\n"
                         "    note print as 'do not quote as current' for every session:\n")
        for src,dst,ti in fresh:
            sys.stderr.write("      notes/%-4d now overturns notes/%-4d  %s\n"
                             %(src,dst,(ti or '')[:56]))
        sys.stderr.write("    If any is unintended, the quoting note needs "
                         "'<!-- notedb: no-supersede -->'.\n")
    if BADSTATUS:
        sys.stderr.write("\n*** UNKNOWN notedb:status= override -- IGNORED, the keyword\n"
                         "    classifier was used instead. Valid: %s\n"%', '.join(VALID_STATUS))
        for nid,v in BADSTATUS:
            sys.stderr.write("      notes/%-4d declares status=%s\n"%(nid,v))
    if DUPES:
        sys.stderr.write("\n*** DUPLICATE NOTE NUMBERS -- two sessions claimed the same id.\n"
                         "    Only the earlier-created file is indexed; RENAME the other.\n")
        for nid,paths in DUPES:
            sys.stderr.write("    notes/%d:\n"%nid)
            for k,q in enumerate(paths):
                sys.stderr.write("      %-8s %s\n"%("INDEXED" if k==0 else "DROPPED",
                                                     os.path.basename(q)))
        sys.exit(3)

def _stale_warning():
    """The index silently served a 121-note-stale record (2026-09-06): notes 577-722 --
    the entire live frontier -- were absent, so `verdict` answered every isolation query
    with notes/560/563/571 while notes/660-674 held the current state, and `stale` could
    not see a single edge added after 576.  Nothing reported an error: a stale index and a
    current one look identical at the prompt.  So compare the newest indexed id against
    the newest file on disk, on EVERY read, and say so loudly."""
    try:
        disk = max(n for n, _ in note_files())
    except ValueError:
        return
    try:
        db = sqlite3.connect('file:%s?mode=ro' % DB, uri=True)
        top = db.execute("SELECT MAX(id) FROM notes").fetchone()[0] or 0
        db.close()
    except Exception:
        return
    if disk > top:
        sys.stderr.write(
            "*** INDEX IS STALE: notes/%d is on disk, the index stops at notes/%d "
            "(%d unindexed). Answers below OMIT them. Run: python3 tools/notedb.py build\n"
            % (disk, top, disk - top))

def _conn():
    if not os.path.exists(DB): sys.exit("no index; run: python3 tools/notedb.py build")
    _stale_warning()
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
    live,dead,self_ret=[],[],[]
    for nid in ids:
        sup=superseded_by(c,nid)
        st=c.execute("SELECT status FROM notes WHERE id=?", (nid,)).fetchone()[0]
        # A note that RETRACTED ITSELF must never head the CURRENT list.  notes/720 says in
        # its own banner "Do not cite this note for anything" and was still printed as line 2
        # of `verdict 0xa70` -- the query a session runs precisely to find out what to trust.
        if st=='retracted': self_ret.append((nid,sup))
        elif sup: dead.append((nid,sup))
        else: live.append((nid,sup))
    print("=== CURRENT (newest first) ===")
    for nid,_ in live[:8]:
        t,d,st=c.execute("SELECT title,date,status FROM notes WHERE id=?", (nid,)).fetchone()
        warn=" [!tag: title says otherwise]" if _tag_conflict(st,t) else ""
        print("  notes/%-3d [%-9s] %s  %s%s"%(nid,st,d,t[:78],warn))
    if self_ret:
        print("\n=== SELF-RETRACTED -- the note withdrew its own claims ===")
        for nid,_ in self_ret[:6]:
            t,d,_x=c.execute("SELECT title,date,status FROM notes WHERE id=?", (nid,)).fetchone()
            print("  notes/%-3d %s  %s"%(nid,d,t[:78]))
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
    mem=[r[0] for r in c.execute("SELECT DISTINCT path FROM mem WHERE val=? ORDER BY path",(a,))]
    if not rows:
        # A silent miss reads exactly like a real negative.  1-2 digit values are deliberately
        # not indexed (they are offsets and flags), so say that rather than imply nobody
        # measured it -- this tool's whole job is to stop a negative being manufactured.
        if len(a)-2 < 3:
            print("%s is BELOW THE INDEXING FLOOR (1-2 hex digits are offsets/flags, not\n"
                  "  addresses, and are not indexed). This is NOT a measured negative --\n"
                  "  grep notes/ directly for it."%a)
        elif mem:
            print("no NOTE mentions %s -- but %d MEMORY file(s) do:"%(a,len(mem)))
            for f in mem: print("    memory/%s"%f)
        else:
            print("no notes mention %s"%a)
            print("  (searched notes/ + memory/. RULE 1 also requires "
                  "extracted/psdevwiki/ps3/ -- grep it before calling this a negative.)")
        return
    print("notes touching %s:"%a)
    for nid,st,d,t in rows:
        sup=superseded_by(c,nid)
        mark=("  <-- SUPERSEDED by "+", ".join("notes/%d"%s for s in sup)) if sup else ""
        warn=" [!tag: title says otherwise]" if _tag_conflict(st,t) else ""
        print("  notes/%-3d [%-9s] %s  %s%s%s"%(nid,st,d,t[:66],mark,warn))
    if mem:
        print("also in MEMORY (not note-indexed, RULE 1 step 1 covers these too):")
        for f in mem: print("    memory/%s"%f)

def show(nid):
    db=_conn(); c=db.cursor()
    r=c.execute("SELECT title,date,status,path FROM notes WHERE id=?", (int(nid),)).fetchone()
    if not r: sys.exit("no notes/%s"%nid)
    t,d,st,p=r
    print("notes/%s  [%s]  %s\n  %s\n  %s"%(nid,st,d,t,p))
    if _tag_conflict(st,t):
        print("  ** TAG/TITLE CONFLICT: tagged [negative] but the title asserts a positive."
              "\n     The tag is a body-keyword summary; the TITLE is the note's headline. **")
    sup=superseded_by(c,int(nid))
    if sup: print("  ** SUPERSEDED BY: %s **"%", ".join("notes/%d"%s for s in sup))
    # EPISODES. A note can supersede ITSELF: notes/117 opens with "878 ... left untried"
    # and later carries "Final: 878 tested". Per-note status cannot express that, and two
    # later notes quoted the stale half. List the episodes so the tail is never missed.
    try:    secs = sections(open(p).read())
    except Exception: secs = []
    if len(secs) > 1:
        print("  ** %d EPISODES -- a later one may supersede the earlier. READ TO THE END: **"%len(secs))
        for k,h in enumerate(secs): print("       %d. %s"%(k+1,h[:88]))
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


# A note whose TITLE asserts a measured positive while the body-keyword classifier tagged
# it [negative].  The status patterns scan the WHOLE BODY, so one "does not" or the word
# "negative" anywhere -- including in a sentence REVERSING a negative, which is what
# notes/236 does ("it reverses the load-bearing negative") -- outranks the headline.
# notes/237 "THE OVERFLOW FIRED ON SILICON" and notes/238 "CONTROL PASSED" are both filed
# [negative]; a session skimming verdict output reads the tag and the title as opposites.
# This is REPORTED, not auto-corrected: requiring the keyword in a heading instead would
# reclassify 171 of 680 notes, which is a judgement call for the sessions that own the
# topics, not something an index should do silently.
TITLE_POS = re.compile(r'\b(FIRED|WORKS?|WORKING|PROVEN|CONFIRMED|SOLVED|RESOLVED|EXECUTED|'
                       r'SUCCEEDS?|DELIVERS?|DELIVERED|RUNS|PASSED|FOUND|LANDS?|LANDED|'
                       # 'OPEN' is a STATUS word here, not an assertion of success:
                       # notes/265 is titled "the IDX bounds question is OPEN: my checker
                       # failed its negative control" and was read as claiming a positive.
                       r'REACHED|ACHIEVED|DECODED|MAPPED|CRACKED|OPENED|OPENS)\b')
# re.I is REQUIRED and its absence was a bug (`token-guardian`, 2026-09-06): titles here mix
# case, so lowercase "does not" / "cannot" never matched and four notes were flagged as
# tag/title conflicts when their titles plainly state a negative result -- notes/221 ("the
# overflow still does not trigger on silicon") is a correctly-tagged negative that the audit
# called a false label, and the §21 fix then acted on that and mislabelled it `info`.
TITLE_NEG = re.compile(r'\b(NOT|NEVER|NO|CANNOT|FAILS?|DEAD|REFUSED|BLOCKED|UNREACHABLE|'
                       r'INERT|ZERO)\b', re.I)
def _tag_conflict(status, title):
    return status=='negative' and bool(TITLE_POS.search(title)) and not TITLE_NEG.search(title)

NEG_KEYWORD = re.compile(r'\bhonest negative\b|\bdoes NOT\b|\bNEGATIVE\b', re.I)

def tagaudit():
    """notedb.py tagaudit -- notes whose body reads negative while their TITLE asserts a positive.

    MEASURES THE BODY, NOT THE FINAL TAG, and that distinction is the whole point.  The status
    classifier is now gated on `not _tag_conflict(...)`, and this audit used to report
    `_tag_conflict` on the FINAL status -- so it could not trip by construction and printed
    "0 of 284 notes" as though that were a measurement.  It was a tautology: the detector had
    been wired to its own remedy.  (`token-guardian`, 2026-09-06, with the probe below.)

    So the audit now asks the pre-gate question -- does the BODY carry a negative keyword while
    the TITLE asserts a positive? -- which is the thing that was ever worth knowing, and it
    reports how many of those the gate is currently suppressing.
    """
    db=_conn(); c=db.cursor()
    # SELF-CHECK FIRST: a synthetic note that MUST be flagged.  If this stops tripping, the
    # detector has been disabled by some later change and every "0 conflicts" below is void.
    probe = "# PROVEN: the widget FIRED on silicon\n\nIt does NOT matter.\n"
    ptitle = title_of(probe)
    if not (_tag_conflict('negative', ptitle) and NEG_KEYWORD.search(probe)):
        print("*** SELF-CHECK FAILED: the built-in must-trip probe does not trip.")
        print("    This audit cannot detect anything; do not read a clean result below.\n")
    else:
        print("self-check: built-in must-trip probe TRIPS -- the detector can still fire.\n")
    rows=c.execute("SELECT id,status,date,title,body FROM notes ORDER BY id").fetchall()
    bad=[(i,st,d,t) for i,st,d,t,body in rows
         if _tag_conflict('negative', t) and NEG_KEYWORD.search(body or '')]
    print("BODY/TITLE CONTRADICTIONS -- the body carries a negative keyword while the")
    print("title asserts a positive. The TITLE is the note's headline and is authoritative;")
    print("the body keyword is what the classifier would otherwise have tagged it on.\n")
    for nid,st,d,t in bad:
        sup=superseded_by(c,nid)
        mark=("  <-- also SUPERSEDED by "+", ".join("notes/%d"%s for s in sup)) if sup else ""
        print("  notes/%-3d [%s] %s  %s%s"%(nid,st,d,t[:84],mark))
    supp=sum(1 for i,st,d,t in bad if st!='negative')
    print("\n  %d notes whose BODY reads negative while their TITLE asserts a positive."%len(bad))
    print("  of those, %d are suppressed by the classifier gate (they do NOT carry the"%supp)
    print("  [negative] tag), and %d still do and want an owner's judgement."%(len(bad)-supp))

# ---------------------------------------------------------------------------
SELFTEST = {568:False, 571:False, 541:False, 542:False, 529:True,  551:True,
            205:False, 218:False, 310:False, 387:False, 471:False, 142:True,
            469:True,  363:False, 454:False}
def selftest():
    """python3 tools/notedb.py selftest -- known-answer cases for the retraction
    classifier. Every one of these was a real misclassification at some point:
      568 passing mention of another note's retraction   -> NOT self
      205/218/310/387/471 label-position heading, object named in the TITLE -> NOT self
      469 "[RESULT 3 RETRACTED by notes/471]"  passive   -> IS self
      142/529/551 genuine self-retractions               -> IS self
    Run this after ANY change to _self_retracted / _retracts_other / _HEAD_PREFIX."""
    import glob
    bad = 0
    for n, exp in sorted(SELFTEST.items()):
        f = glob.glob(os.path.join(os.path.dirname(__file__), '..', 'notes', '%d-*.md' % n))
        if not f:
            print("  notes/%-4d MISSING" % n); continue
        got = _self_retracted(open(f[0], errors='replace').read(), n)
        if got != exp: bad += 1
        print("  notes/%-4d expect=%-5s got=%-5s %s" % (n, exp, got, "OK " if got == exp else "**WRONG**"))
    print(("\n  ALL %d CORRECT" % len(SELFTEST)) if not bad else "\n  *** %d WRONG ***" % bad)
    return 0 if not bad else 1


# The entry point must stay LAST: it was previously above selftest(), so `notedb.py
# selftest` fell through to the help text because the name did not exist yet.
if __name__=='__main__':
    a=sys.argv[1:] or ['--help']
    # 'reindex'/'rebuild' are aliases for build: both appear in the working notes and in
    # session briefs, and an unrecognised verb used to print the help text and exit 0 --
    # so `notedb.py reindex` looked like it had reindexed and had not.  An unknown verb
    # now exits NONZERO (RULE 3: a tool must not pass clean without doing the work).
    if   a[0] in ('build','reindex','rebuild'): build()
    elif a[0]=='verdict':  verdict(' '.join(a[1:]))
    elif a[0]=='addr':     addr(a[1])
    elif a[0]=='show':     show(a[1])
    elif a[0]=='stale':    stale()
    elif a[0]=='tagaudit': tagaudit()
    elif a[0]=='selftest': sys.exit(selftest())
    elif a[0] in ('--help','-h','help'): print(__doc__)
    else:
        sys.stderr.write("notedb: unknown command %r\n\n" % a[0]); print(__doc__); sys.exit(2)
