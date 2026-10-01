#!/usr/bin/env python3
"""Provision only the caller's empty disposable fixture directory."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
assert not any(root.iterdir()), "fixture directory must be empty"
(root / "tokens").mkdir()
(root / "softhsm2.conf").write_text(f"directories.tokendir = {root}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n")
os.environ["SOFTHSM2_CONF"] = str(root / "softhsm2.conf")
pin = secrets.token_hex(16)
for label in ("token1", "token2"):
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", label,
                    "--so-pin", secrets.token_hex(16), "--pin", pin],
                   check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
(root / "config.json").write_text(json.dumps({"Path": "/usr/lib/softhsm/libsofthsm2.so",
    "TokenLabel": "token1", "Pin": pin, "Plaintext": secrets.token_hex(24), "MaxSessions": 4}))
(root / "config.json").chmod(0o600)
