import json
from pathlib import Path

import pytest

OUT = Path(__file__).parent / ".results.json"
_results = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when != "call":
        return
    meta = getattr(item.function, "_rt", None)
    if meta is None:
        return
    evidence = ""
    if rep.failed:
        evidence = str(call.excinfo.value).strip().splitlines()[0][:400] if call.excinfo else ""
    _results.append({**meta, "test": item.nodeid.split("/")[-1],
                     "bypassed": bool(rep.failed), "evidence": evidence})


def pytest_sessionfinish(session):
    OUT.write_text(json.dumps(_results, indent=1))
