"""Build redteam/01_results.md from redteam/attacks/.results.json.

    python -m pytest redteam/attacks -q -p no:cacheprovider ; python redteam/make_results.py
"""
import collections
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).parent
rows = json.loads((HERE / "attacks" / ".results.json").read_text())
VECTORS = {1: "Action splitting", 2: "Parameter smuggling", 3: "Context forgery", 4: "Prompt injection",
           5: "Multi-agent collusion", 6: "Race / TOCTOU", 7: "Replay", 8: "Policy gaps", 9: "Fail-open",
           10: "Log tampering", 11: "Gate bypass", 12: "Canonicalization", 13: "Signature verification",
           14: "Key exposure", 15: "Time", 16: "CONSTRAIN / ESCALATE", 17: "Crash recovery",
           18: "Policy downgrade"}
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}
commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                        cwd=HERE).stdout.strip()


def esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


out = ["# Red-team results — MCC-Core", "",
       f"Target commit `{commit}` (branch `main`, merge of PR #128). No source file was modified.",
       "",
       "Every test asserts the **secure** property, so *bypassed = yes* means the test failed: the",
       "attack got through. A bypass is only claimed where the recording actuator was actually invoked",
       "(or, for the audit and static checks, where the named verifier accepted the tampered input).",
       "",
       "`kind` separates what the result means:",
       "",
       "- **bypass** — the system did something its own policy/doctrine says it must not.",
       "- **design-gap** — behaves as coded, but the behaviour leaves an authority hole worth a decision.",
       "- **hardening** — not exploitable through the governed path today; removes a foot-gun or a "
       "second line of defence that is missing.",
       "- **known-limitation** — already documented by the project; re-tested for exploitability only.",
       ""]
yes = [r for r in rows if r["bypassed"]]
out += [f"**{len(rows)} attack cases run: {len(rows) - len(yes)} blocked, {len(yes)} got through.**", "",
        "| kind | critical | high | medium | low |", "|---|---|---|---|---|"]
for kind in ("bypass", "design-gap", "hardening", "known-limitation"):
    c = collections.Counter(r["severity"] for r in yes if r["kind"] == kind)
    out.append(f"| {kind} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} |")
out += ["", "## Per vector", "", "| # | vector | cases | blocked | got through |", "|---|---|---|---|---|"]
for v, name in VECTORS.items():
    rs = [r for r in rows if r["vector"] == v]
    y = sum(r["bypassed"] for r in rs)
    out.append(f"| {v} | {name} | {len(rs)} | {len(rs) - y} | {y} |")

out += ["", "## Cases that got through", "",
        "| vector | test | bypassed | severity | kind | evidence |", "|---|---|---|---|---|---|"]
for r in sorted(yes, key=lambda r: (SEV[r["severity"]], r["kind"] != "bypass", r["vector"])):
    out.append(f"| {r['vector']} {VECTORS[r['vector']]} | `{esc(r['test'])}` | yes | {r['severity']} | "
               f"{r['kind']} | {esc(r['evidence'])} |")

out += ["", "## Cases that were blocked", "",
        "| vector | test | bypassed | severity | what was attempted |", "|---|---|---|---|---|"]
for r in sorted([r for r in rows if not r["bypassed"]], key=lambda r: r["vector"]):
    out.append(f"| {r['vector']} {VECTORS[r['vector']]} | `{esc(r['test'])}` | no | {r['severity']} | "
               f"{esc(r['title'])} |")
(HERE / "01_results.md").write_text("\n".join(out) + "\n")
print(f"{len(rows)} cases, {len(yes)} through")
