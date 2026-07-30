# SPIKE: differential bypass fuzzer

`src/bypass_fuzz.py`, `tests/test_bypass_fuzz.py`. Branch `spike/bypass-fuzzer` off `main` at 6730c1e.

Take a payload the stack blocks today. Mutate it. Keep the mutations a reader would
still call the same attack and the stack no longer blocks. Nothing is mocked:
detection runs through the real `PolicyEngine`, `InputInspector` and
`MetadataInspector`, wired in the order and with the blocking rule `src/proxy.py`
uses, over the committed `config/default_policy.yaml`.

```bash
python -m src.bypass_fuzz --json reports/bypass_fuzz.json --md reports/bypass_fuzz.md
python -m src.bypass_fuzz --trials 20 --limit-seeds 3      # a fast look
```

Every number below is from **seed 20260730**, printed in the report and in the
Markdown header. Two runs at that seed produce byte-identical JSON. The run takes
89 seconds single-threaded.

## The numbers

| | |
|---|---|
| seeds, argument side | 32 |
| seeds, metadata side | 32 |
| candidates generated | 5909 |
| still blocked | 1464 |
| **rejected by the oracle** | **1202** |
| **surviving bypasses** | **967** |
| of those, one operator | 820 |
| of those, needing a combination | 147 |
| **distinct holes** | **21** |
| **holes with no prior art** | **19** |
| holes needing no decoder assumption | 10 |

Argument seeds are the 32 single-step attack payloads that the stack blocks today
and whose blocking text is not an ANSI escape (see the oracle limits). Metadata
seeds are the eight real servers in `tests/fixtures/real_servers/`, each with its
first tool's description replaced by one of four poison strings, one per critical
`METADATA_PATTERNS` entry: 32 poisoned catalogue entries the inspector drops today.

967 survivors is not 967 findings. Every surviving chain is delta-debugged down to
the operators that are individually load-bearing before it is grouped, which is
what turns 967 into 21.

Re-running at seed 7 finds 960 survivors and the **same 21 holes**, identical root
cause for root cause. The search saturates; the seed changes which spellings you
see, not which holes.

## The oracle

**A mutant is still the attack when some recovery pipeline reproduces the exact
text the stack blocked over.**

Not the whole argument, and not "looks similar". `RealStack` records the
`matched_text` of the finding that produced the block, and that string is the
seed's core. For `pi-001` it is `Ignore all previous instructions`; for `en-001`,
which blocks on a `decoded:base64` view, it is the decoded phrase and not the
base64 that carried it. Comparison happens in a **core form**: tag characters
unwrapped, format characters and combining marks and variation selectors dropped,
NFKC folded, a full confusable table folded unconditionally, casefolded, all
whitespace removed.

Two pipelines, reported separately because they cost different amounts of belief:

- **`direct`** is presentation only. The mutant carries the payload and a reader
  needs nothing but literacy. 10 of the 21 holes are reachable this way.
- **`decoded`** adds unbounded base64 / base64url / base32 / hex / percent
  decoding to a fixpoint, whitespace-insensitive, with adjacent runs tried
  concatenated. The remaining 11 holes need it.

### What the oracle refuses

Paraphrase. `synonym_swap` rewrites `ignore all previous instructions` as
`disregard every directive issued before this line`, a human calls that the same
attack, and the oracle rejects it because the core form differs. 1202 candidates
died here, most of them paraphrases and payload-destroying encodings. The oracle
under-reports on purpose; the 967 are a lower bound.

### Limits, stated

1. **It is string recovery, not semantics.** A real attacker rewrites the
   sentence. This tool cannot see that class of bypass at all, and the two
   `tool_poisoning` known gaps (`tp-002`, `tp-003`) are exactly that class.
2. **`decoded` survivors rest on a claim about the reader.** The stack does not
   decode base32 or a fourth base64 layer. Whether a model does is not something
   this module measures. Those 11 holes are real gaps in the *detector*; calling
   them exploitable is a separate argument, and the report tags every finding with
   the pipeline that recovered it so the two are never conflated.
3. **A short core weakens it.** When a policy rule fires on `chmod\s+777` the core
   is eight characters, and preserving eight characters is easier than preserving
   a sentence. Defensible in the sense that the core *is* what the rule blocked
   for, but it is a weaker claim than for a phrase payload.
4. **Terminal payloads are excluded, not solved.** `ti-001` through `ti-003` block
   on an ANSI escape, whose consumer is a terminal emulator, and a terminal does
   not strip zero-width spaces the way a reader does. A zero-width space inside
   `ESC[2J` is a dead sequence, not a hidden one, so fuzzing those seeds would
   manufacture bypasses that are really broken strings. `_oracle_applies` drops
   them.
5. **Structural findings are reachability, not consumption.** `key_name` puts the
   payload in a JSON object key. It is model-visible in the wire JSON, but whether
   a given client renders it into the model's context is client-dependent.
6. **A bypass of detection is not a demonstrated exploit.** The seeds are payloads
   the project already decided were worth blocking; this measures whether the same
   content still gets blocked, not what happens downstream.

## Findings, grouped by root cause

`new` means no payload in the 65-payload corpus and none of the 11 `known_gap`
entries covers it. `defeats` is `kind@component`: the component that used to block
after the `@`, and before it one of four mechanical probes, in order. Not present
in any leaf the walker yields: **walker**. Blocks again once every normalization
budget is lifted: **budget**. The views production really built still carry the
payload text modulo case and whitespace runs, and nothing fired: **pattern**.
Otherwise normalization never delivered the payload to the signatures:
**normalizer**.

### Normalizer: the transform set is an enumeration

| hole | new | oracle | seeds |
|---|---|---|---|
| confusable table is an enumeration, not a script-mixing rule | yes | direct | 49 |
| combining marks are neither stripped nor rejected | yes | direct | 49 |
| variation selectors are absent from the invisible class | yes | direct | 28 |
| invisible characters are stripped rather than decoded, so tag-encoded text vanishes | yes | direct | 14 |
| whitespace is collapsed, never removed, so intra-word splits survive | yes | direct | 23 |
| whitespace collapse deliberately preserves newlines | yes | direct | 22 |

Small capitals and Cherokee are not in `_CONFUSABLES`, so `ɪɢɴᴏʀᴇ ᴀʟʟ ᴘʀᴇᴠɪᴏᴜꜱ
ɪɴꜱᴛʀᴜᴄᴛɪᴏɴꜱ` passes. `_INVISIBLE_CLASS` covers U+200B-200F, U+202A-202E, tags and
soft hyphen but not U+FE00-FE0F, so a variation selector between two letters is
invisible to a human and opaque to the pattern. Non-composing combining marks
(U+0335 and friends) survive NFKC and are not stripped at all.

`tag_smuggle` is the one that deserves its own line. The Unicode tag block **is**
covered by the stripper, and that is the problem: stripping is not decoding. The
canonical view of a tag-encoded payload is empty, nothing matches, and unlike the
metadata side, the argument side has no "presence of an invisible character is
itself a finding" rule. The published ASCII-smuggling attack passes clean.

### Normalizer: the decoders do not cover their own alphabets

| hole | new | oracle | seeds |
|---|---|---|---|
| decoded fragments are never concatenated before matching | yes | decoded | 46 |
| MIN_BASE64_FRAGMENT skips short runs | yes | decoded | 55 |
| the base64 run regex rejects a run with excess padding | yes | decoded | 63 |
| the base64 run regex does not include the base64url alphabet | yes | decoded | 1 |
| no base32 decoder exists | yes | decoded | 63 |
| the hex run regex requires unseparated bytes | yes | decoded | 63 |
| MAX_DECODE_DEPTH stops one layer short of a fourth wrapper | no (`en-004`) | decoded | 63 |
| policy pattern rules default to decoded views off | no (`en-001`, `en-005`) | decoded | 22 |

Two of these are cheap to argue about and cheap to fix. Splitting base64 on
whitespace defeats detection because `_decode_fragments` decodes each run
independently and never tries adjacent runs concatenated, while `base64 -d`
and any reader do exactly that. Three trailing `=` instead of one defeats
`_BASE64_RUN_RE` entirely, because `={0,2}` followed by `(?![A-Za-z0-9+/=])`
cannot match a third.

`base64url` shows one seed only because most payloads' base64 happens to contain
no `-` or `_`; the operator declines rather than emit an unchanged string. The
hole is not one seed wide.

### View composition: the two halves of normalization never meet

| hole | new | oracle | chains |
|---|---|---|---|
| decoded views are built from the raw string, so a presentation trick inside an encoded run is undone by neither the stripper nor the decoder | yes | decoded | 43 single + 31 combined |

The largest single finding, and the one no existing payload comes near.
`Normalizer.canonical` and `Normalizer.decoded_views` both run on the *original*
text. Neither runs on the other's output. So:

- a zero-width space inside the base64 of `en-001` breaks `_BASE64_RUN_RE`, and
  the canonical view that would have removed it is never fed to the decoder;
- fullwidth-spelled base64 is folded by NFKC in the canonical view, but the
  decoder never sees the canonical view;
- a payload that is base64-encoded *after* soft hyphens are inserted decodes back
  to text containing soft hyphens, into a decoded view that is never canonicalized.

`ob-001` proves a zero-width space in prose is recovered. It says nothing about a
zero-width space in the base64 that carries the prose, and the two are different
bugs: the first is fixed by the canonical view, the second is fixed by nothing.

### Budget: every documented limit is spendable by the attacker

| hole | new | oracle | seeds |
|---|---|---|---|
| MAX_FRAGMENTS_PER_STRING is spendable | yes | decoded | 57 |
| MAX_DECODED_BYTES_TOTAL is spendable | yes | decoded | 54 |
| MAX_INPUT_CHARS drops every normalized view rather than the tail | yes | direct | 51 |
| an oversized metadata leaf is skipped entirely rather than truncated | yes | direct | 32 |

Prefix 40 decodable decoys and the 33rd fragment, the real one, is never decoded.
Prefix a megabyte of filler and `Normalizer.views` logs a warning and returns the
raw view alone, so every obfuscation payload in `ob-*` starts working again.
Prefix 24KB to a tool description and `MetadataInspector._scan_leaf` skips it.
Each of these is a fail-open on volume, and the payload is byte-identical to one
the stack blocks.

`oversize_leaf` and `MAX_DESCRIPTION_CHARS` deserve a note: the oversize signal is
deliberately `low` and can never reach a threshold on its own, which is documented
and defended in `inspector.py`. The fuzzer did not discover an oversight there. It
discovered that the *scan cap* above it drops the leaf entirely, which is a
different decision and is not defended anywhere.

### Walker: what gets looked at

| hole | new | oracle | seeds |
|---|---|---|---|
| the argument and result walkers skip dict key names | yes | direct | 20 |
| policy conditions address one named top-level argument, so wrapping the value takes it out of scope | yes | direct | 2 |

`iter_string_leaves` is called with `include_keys=True` only by
`MetadataInspector`. `InputInspector._iter_strings` and `result_leaves` both leave
it False, so a payload in a key name is never scanned on the argument or result
side. The comment on `StringLeaf` explains why a key cannot be *rewritten*; it
does not explain why it is not *read*.

`nested_array` shows only 2 seeds because `pattern_match` does `str(value)` on the
whole argument, and a dict's `repr` usually still contains the payload. That is an
accident, not a defence: it breaks the moment the payload contains a quote.

### What did not survive

- **Every operator the corpus already covers, when applied to plain text.**
  Zero-width, bidi override, fullwidth, soft hyphen and case scrambling on a
  plaintext payload are all still caught. `ob-001` through `ob-005` hold up. The
  canonical view does its job.
- **Paraphrase**, by construction of the oracle rather than by the stack.
- **`schema_default` alone.** Moving a payload into a JSON Schema `default` is
  still caught: the metadata walker is generic and reaches it, and a finding in a
  non-prose leaf escalates to dropping the tool.
- **`nested_array` and `key_name` on the metadata surface.** `include_keys=True`
  and the generic walk cover both.

## Verdict: periodic tool, not a CI gate

**Not CI, for three reasons.**

1. Nothing here should gate a merge, because a run either finds these 21 holes
   again (it will, until they are fixed) or it finds nothing new. A gate that
   fails every build is off within a week.
2. 89 seconds is too slow for the default suite and the memory profile is spiky:
   the budget operators build megabyte strings on purpose.
3. The oracle's `decoded` half rests on an assumption about the reader. That
   belongs in a review conversation, not in a pass/fail exit code.

**What does belong in CI** is what is already there: `tests/test_bypass_fuzz.py`,
67 tests, under a second. Operators, both oracle pipelines, the attribution
probes, determinism under a fixed seed, and one seeded smoke run over a single
seed and five operators. Notably `test_the_extended_confusable_table_is_not_already_folded`
fails if `_CONFUSABLES` grows to cover one of the fuzzer's characters, so an
operator can never quietly stop testing anything.

**How to use it.** Run it by hand after any change to `src/normalize.py`,
`INJECTION_PATTERNS`, `METADATA_PATTERNS` or a walker, and once a release. Compare
the hole count against this document. A new row is a regression; a missing row is
a fix worth a payload.

**On turning findings into payloads.** Deliberately not done here, and
`attacks/payloads.yaml` is untouched. Most of these 21 are one-line fixes in
`src/normalize.py` (fold the decoder alphabets, canonicalize before decoding,
concatenate adjacent runs, extend the invisible class), and a payload written
against a hole that is about to close is a payload that only ever tests a fixed
bug. The four that are not one-liners, and that want payloads whatever happens to
the rest, are the budget four: fragment flood, decoded-byte flood, input-size
overflow, and oversized metadata leaf. Those are policy decisions about fail-open
behaviour, not table entries.

## What the tool is bad at

- **It only mutates one string field per seed**, the longest string argument. A
  payload spread across `subject` and `body` is out of reach.
- **It has no notion of the response side.** `ResultInspector`,
  `OutputInspector` and `TerminalSanitizer` are untested by it. `result_leaves`
  skipping a whole content block whose `type` is `image` looks like the same class
  of walker hole as `key_name`, and this spike does not measure it.
- **The composition table is a long tail by construction.** 34 of the 65 minimal
  chains of length two or more are "one listed hole plus another listed hole",
  kept apart only because on that specific seed both were needed. They are not 34
  findings.
- **Novelty is judged against a hand-written `PRIOR_ART` table**, one entry per
  operator. If someone adds a payload covering base32, the table has to be updated
  by hand or the fuzzer will keep calling it new.
