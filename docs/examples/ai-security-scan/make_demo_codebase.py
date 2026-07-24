#!/usr/bin/env python3
"""Generate a reproducible demo codebase: 8 planted vulnerabilities hidden in
~200 benign files, so you can measure the scan's recall and token savings.
Usage: make_demo_codebase.py <dir>   (default ./demo-src)
"""
import os, random, sys
OUT = sys.argv[1] if len(sys.argv) > 1 else "./demo-src"
os.makedirs(OUT, exist_ok=True)
random.seed(9)

VULNS = {
 "user_db.py": 'import sqlite3\ndef get_user(conn, username):\n    # user input concatenated into the query\n    q = "SELECT * FROM users WHERE name = \'" + username + "\'"\n    return conn.execute(q).fetchone()\n',
 "report_export.py": 'import subprocess\ndef export(fmt, filename):\n    subprocess.run(f"pandoc {filename} -o out.{fmt}", shell=True)\n',
 "auth_hash.py": 'import hashlib\ndef store_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n',
 "config_secrets.py": 'STRIPE_SECRET_KEY = "EXAMPLE_hardcoded_secret_placeholder_not_a_real_key"\nDB_PASSWORD = "EXAMPLE_hardcoded_db_password_placeholder"\n',
 "file_read.py": 'def read_note(base, name):\n    return open(base + "/" + name).read()\n',
 "calc_api.py": 'def compute(expr):\n    return eval(expr)\n',
 "token_gen.py": 'import random\ndef make_reset_token():\n    return "".join(random.choice("0123456789abcdef") for _ in range(16))\n',
 "xml_parse.py": 'import xml.etree.ElementTree as ET\ndef parse(data):\n    return ET.fromstring(data)\n',
}
for name, code in VULNS.items():
    open(os.path.join(OUT, name), "w").write(code)

TPL = [
 "def add(a, b):\n    return a + b\n\ndef mul(a, b):\n    return a * b\n",
 "class Cache:\n    def __init__(self):\n        self._d = {}\n    def get(self, k):\n        return self._d.get(k)\n",
 "import logging\nlog = logging.getLogger(__name__)\ndef handle(e):\n    log.info('handling %s', e['id'])\n    return {'ok': True}\n",
 "def normalize(items):\n    return [x.strip().lower() for x in items if x]\n",
]
for i in range(200):
    body = random.choice(TPL) + f"\n# module {i}\nVERSION = '{i}.0'\n" + \
        "".join(f"def helper_{i}_{j}(x):\n    return x * {j}\n" for j in range(random.randint(3, 9)))
    open(os.path.join(OUT, f"module_{i:03d}.py"), "w").write(body)

n = len(os.listdir(OUT))
loc = sum(len(open(os.path.join(OUT, f)).readlines()) for f in os.listdir(OUT))
print(f"wrote {n} files, {loc} lines, {len(VULNS)} planted vulnerabilities to {OUT}/")
