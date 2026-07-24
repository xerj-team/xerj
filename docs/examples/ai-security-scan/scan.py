#!/usr/bin/env python3
"""Token-efficient AI security triage over a large codebase.

An AI cannot hold a 50k-line codebase in its context window, and loading it all
to "review for vulnerabilities" is slow and expensive. Instead: index the code
once with `xerj autoindex ./src`, then this script searches XERJ for the
distinctive token signatures of common vulnerability classes and prints only
the FLAGGED chunks — file, pattern, and the surrounding code — for an AI (or a
human) to review.

You review a handful of suspect snippets, not the whole tree. On the bundled
demo that is ~57x fewer tokens at 8/8 recall of the planted issues.

Usage:
    xerj --insecure --data-dir ./data &
    xerj autoindex ./src
    python3 scan.py                 # scans ax-* on localhost:9200

This is TRIAGE, not proof. It surfaces known *patterns* so an AI can judge
exploitability with real context; it does not find novel logic bugs, and recall
depends on the query set below. Treat a hit as "look here", not "confirmed".
"""
import json
import os
import urllib.request

XERJ = os.environ.get("XERJ_URL", "http://localhost:9200")
INDEX = os.environ.get("XERJ_INDEX", "ax-*")

# Distinctive-token queries per vulnerability class. The lesson baked in here:
# query the RARE, characteristic tokens of a pattern, not a verbose sentence —
# common words like "True" or "data" appear everywhere and drown the signal.
CHECKS = [
    ("SQL injection",         "SELECT execute query concatenation username",
     "query built by string-concatenating user input"),
    ("Command injection",     "subprocess shell popen os.system",
     "shell command built from untrusted input"),
    ("Weak password hashing", "md5 sha1 hexdigest password",
     "fast/unsalted hash used for passwords"),
    ("Hardcoded secret",      "secret api_key password credential STRIPE_SECRET_KEY DB_PASSWORD",
     "credential committed into source"),
    ("Path traversal",        "path traversal open read filename user",
     "file path built from user input without sanitisation"),
    ("Unsafe eval/exec",      "eval exec compile expr input",
     "arbitrary code execution from input"),
    ("Insecure randomness",   "random token secret reset",
     "predictable RNG used for a security value"),
    ("Unsafe deserialization","pickle yaml.load marshal load",
     "deserializing untrusted data"),
    ("XXE / unsafe XML",      "xml entity fromstring parse etree",
     "XML parsed with external entities enabled"),
]


def search(query, k=3):
    body = {
        "size": k,
        # search both field names autoindex may use for text (body / text)
        "query": {"bool": {"should": [
            {"match": {"body": query}}, {"match": {"text": query}}]}},
        "_source": ["ax_path", "body", "text", "start_line", "end_line"],
    }
    req = urllib.request.Request(f"{XERJ}/{INDEX}/_search",
                                json.dumps(body).encode(),
                                {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req))["hits"]["hits"]


def snippet(src):
    t = src.get("body") or src.get("text") or ""
    return t if isinstance(t, str) else "\n".join(t)


def main():
    flagged = {}   # path -> (patterns, text)
    for name, query, why in CHECKS:
        for h in search(query, 3):
            s = h["_source"]
            path = s.get("ax_path", h["_id"])
            loc = ""
            if s.get("start_line"):
                loc = f":{s['start_line']}-{s.get('end_line', '')}"
            key = path + loc
            entry = flagged.setdefault(key, ([], snippet(s)))
            if name not in entry[0]:
                entry[0].append(name)

    print(f"\n=== FLAGGED FOR REVIEW ({len(flagged)} chunks) ===\n")
    review_chars = 0
    for key, (patterns, text) in flagged.items():
        review_chars += len(text)
        print(f"── {key}")
        print(f"   patterns: {', '.join(patterns)}")
        for line in text.strip().splitlines()[:12]:
            print(f"   | {line}")
        print()

    # token accounting — the point of the whole exercise
    print("=== TOKEN COST ===")
    print(f"  review only these flagged chunks : ~{review_chars // 4:,} tokens")
    print("  (vs loading the entire codebase into the AI's context — usually")
    print("   orders of magnitude more, and often larger than the window itself)")
    print("\nNext: hand each flagged chunk to your AI and ask it to confirm whether")
    print("the pattern is actually exploitable in context, and cite the file:line.")


if __name__ == "__main__":
    main()
