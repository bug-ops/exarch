"""Fail unless build-system requires pins the maturin version locked in uv.lock.

Prints the locked version on success.
"""

import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else "crates/exarch-python")
with (root / "uv.lock").open("rb") as f:
    packages = tomllib.load(f)["package"]
locked = [p["version"] for p in packages if p["name"] == "maturin"]
with (root / "pyproject.toml").open("rb") as f:
    requires = tomllib.load(f)["build-system"]["requires"]

if len(locked) != 1:
    sys.exit(f"expected exactly one maturin entry in uv.lock, found {locked}")
expected = [f"maturin=={locked[0]}"]
if requires != expected:
    sys.exit(f"[build-system].requires is {requires}, expected {expected}")
print(locked[0])
