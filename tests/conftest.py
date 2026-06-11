import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

# Keep test runs away from the repository's audit.jsonl prior-art chain,
# and keep main.py import free of any live OPA dependency.
os.environ.setdefault(
    "MCC_AUDIT_LOG_PATH",
    os.path.join(tempfile.mkdtemp(prefix="mcc-test-"), "audit.jsonl"),
)
os.environ.setdefault("MCC_USE_OPA", "false")
