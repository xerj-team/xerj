# AI security triage without loading the whole codebase

An AI can't security-review a 50k-line repo — it won't fit in the context
window, and loading it all is slow and expensive. The move that makes it
affordable:

> **Index the code once, search for vulnerability *patterns*, and hand the AI
> only the flagged chunks — with their surrounding code — to judge.**

You review a handful of suspect snippets instead of the whole tree.

## Try it (≈1 minute)

```bash
# 1. make a demo codebase: 8 planted vulns hidden in ~200 benign files
python3 make_demo_codebase.py ./demo-src

# 2. index it — one command
xerj --insecure --data-dir ./data &
xerj autoindex ./demo-src

# 3. triage
python3 scan.py
```

## What it does

`scan.py` runs one XERJ search per vulnerability class (SQL injection, command
injection, weak hashing, hardcoded secrets, path traversal, unsafe eval,
insecure randomness, unsafe deserialization, XXE) and prints only the chunks
that matched — file, `start_line-end_line`, the matched patterns, and the code —
formatted for an AI to confirm.

## Measured on the demo

| | result |
|---|--:|
| planted vulnerabilities | 8 |
| **found in the flagged chunks** | **8 / 8** |
| tokens to review the flagged chunks | **~310** |
| tokens to load the whole codebase | ~17,900 |
| **reduction** | **~57×** |

On a real repo the ratio is far larger — the flagged set stays small while the
codebase grows past the context window entirely.

## The one design lesson (it caused a real miss)

Query the **distinctive tokens** of a pattern, not a verbose sentence. Our first
pass used `"subprocess shell=True command injection"` and *missed* the command
injection — because `True` appears in every Python file and drowned the signal,
floating benign modules to the top. `"subprocess shell popen"` (rare, specific
tokens) catches it cleanly. The `CHECKS` list in `scan.py` is built this way; if
you add a check, pick the rarest words that still identify the pattern.

## Be honest about what this is

- **Triage, not proof.** A hit means "look here," not "confirmed exploitable."
  The point is to shrink what the AI reads so it *can* reason about
  exploitability with real context — then it cites the `file:line`.
- **Finds known patterns, not novel logic bugs.** It won't catch an auth-bypass
  that has no characteristic token. Pair it with real SAST and human review for
  anything that matters.
- **Recall depends on the query set.** The nine checks here cover common
  OWASP-style classes; extend `CHECKS` for your stack (e.g. `dangerouslySet‑
  InnerHTML` for React, `Runtime.exec` for Java).
- **Some cross-matching is expected.** A file may be flagged by more than one
  check; that's fine for triage — the AI de-dupes when it reviews.

## Why it's a good fit for XERJ specifically

Unlike a raw `grep`, each flagged hit comes back as a **chunk with surrounding
code** (autoindex windows line-oriented files), so the AI sees the whole
function and can judge whether the pattern is actually reachable — not just an
isolated line. One index answers every pattern query, and the same approach
works over PDFs, configs, and docs in the same folder.
