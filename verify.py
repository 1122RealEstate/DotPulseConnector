#!/usr/bin/env python3
"""Check this copy of the DotPulse connector against the release it claims to be.

    python3 verify.py            exit 0 and "ok" when every file matches MANIFEST.sha256

Standard library only. It checks that the files are the ones listed and unchanged; that the
manifest itself is the official one is what the pinned commit (hermes plugins install --ref) is for.
"""
import hashlib, os, sys

here = os.path.dirname(os.path.realpath(__file__))
expected = {}
for line in open(os.path.join(here, "MANIFEST.sha256")):
    digest, _, name = line.strip().partition("  ")
    if name:
        expected[name] = digest
problems = []
for name, digest in sorted(expected.items()):
    try:
        actual = hashlib.sha256(open(os.path.join(here, name), "rb").read()).hexdigest()
    except OSError:
        problems.append("falta " + name)
        continue
    if actual != digest:
        problems.append("cambiado " + name)
ignored = {"MANIFEST.sha256", "verify.py", "README.md"}
for root, dirs, files in os.walk(here):
    dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
    for f in files:
        name = os.path.relpath(os.path.join(root, f), here)
        if name not in expected and name not in ignored and not name.endswith(".pyc"):
            problems.append("de más " + name)
if problems:
    print("\n".join(problems))
    sys.exit(1)
print("ok: %d archivos coinciden con el manifiesto" % len(expected))
