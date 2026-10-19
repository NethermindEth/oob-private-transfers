"""Local paths shared by services, tests, and experiment drivers."""
import os
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "core"
TESTBED = Path(os.environ.get("OOB_TESTBED", ROOT / "testbed")).expanduser().resolve()
HALO_KEYS = Path(os.environ.get("OOB_HALO_KEYS", ROOT / ".cache/halo2-keys")).expanduser().resolve()
BENCHLOCK = ROOT / "scripts/benchlock"
ANVIL = Path(os.environ.get("OOB_ANVIL") or shutil.which("anvil") or Path.home() / ".foundry/bin/anvil")
