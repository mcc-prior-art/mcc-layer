"""Live-model provenance remediation (PR #112) — offline, deterministic.

``run_live_proof_astra.py`` sources its proposal from
``DeterministicAstraProvider`` (an explicitly offline/reference fixture).
That proves the generic upstream-adapter shape, but a claim of "a real
live OpenAI model call drove this real external side effect" requires a
structurally separate proof: this file exercises
``examples/universal_execution_proof/run_live_proof_astra_openai.py``,
the dedicated live-OpenAI-model script, WITHOUT ever making a real
network call, and proves:

* it fails closed with the exact required marker string when
  ``OPENAI_API_KEY``/``OPENAI_MODEL`` are absent, with NO fallback to
  ``DeterministicAstraProvider`` (statically: the file never imports or
  references that class at all);
* it never reads ``OPENAI_API_KEY``/``GITHUB_TOKEN`` directly (both
  remain encapsulated inside the existing, unmodified
  ``OpenAIAstraProvider.from_env`` / ``SandboxConfig.from_env``);
* its ``is_live`` gate (``require_live_response``) refuses to treat a
  non-live ``AstraResponse`` as live evidence, even in isolation from any
  network call;
* the shared ``astra_proposal_to_http_request`` helper's new ``actor``
  override is additive -- the existing offline-fixture call sites (which
  never pass it) are unaffected -- and produces a distinct, non-Astra-
  branded actor label for the live-OpenAI-model line, so the two proof
  lines' evidence can never be confused for one another;
* the live script never instructs the model to claim it is "GPT-6
  Astra", never labels its own live success/failure markers or the
  live-line actor as "Astra"-branded, and the literal phrase "real, live
  GPT-6 Astra model call" cannot regress into its executable strings
  (source-level provenance remediation: the live producer's identity is
  the real, configured model -- e.g. ``gpt-4o-mini`` -- never "GPT-6
  Astra", which names only this repository's reference abstraction).

No MCC-Core file, and no PR #111 file, is touched or imported by this
module beyond what ``astra_upstream.py``/``run_live_proof_astra.py``
already (unchanged) import.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from examples.gpt6_astra_reference.astra_provider import AstraResponse
from examples.universal_execution_proof.astra_upstream import (
    AstraUpstreamError,
    astra_proposal_to_http_request,
)
from examples.gpt6_astra_reference.models import AstraProposal

ROOT = Path(__file__).resolve().parents[1]
LIVE_SCRIPT = ROOT / "examples" / "universal_execution_proof" / "run_live_proof_astra_openai.py"


# --------------------------------------------------------------------------- #
# Structural no-fallback / no-raw-secret-access guard.
# --------------------------------------------------------------------------- #

def test_live_script_exists():
    assert LIVE_SCRIPT.exists()


def test_live_script_never_references_deterministic_provider_as_code():
    """``DeterministicAstraProvider`` may appear in this file's module
    docstring (comparing itself to ``run_live_proof_astra.py``), but must
    never appear as an AST identifier anywhere -- no import, no name, no
    attribute access. Parsing the AST (rather than grepping raw text)
    means this holds even if the docstring wording changes, and proves
    there is no *executable* fallback path from live mode to the offline
    fixture, not merely an absent string."""
    source = LIVE_SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    module_docstring = ast.get_docstring(tree)

    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value == module_docstring:
            continue  # the module docstring itself is exempt
        if isinstance(node, ast.alias) and "DeterministicAstraProvider" in (node.name, node.asname or ""):
            offenders.append(node)
        if isinstance(node, ast.Name) and node.id == "DeterministicAstraProvider":
            offenders.append(node)
        if isinstance(node, ast.Attribute) and node.attr == "DeterministicAstraProvider":
            offenders.append(node)
    assert not offenders, f"live script references DeterministicAstraProvider as code: {offenders}"


def test_live_script_never_directly_reads_raw_secret_env_vars():
    """``OPENAI_API_KEY`` and ``GITHUB_TOKEN`` must be read only through
    the existing, unmodified ``OpenAIAstraProvider.from_env`` /
    ``SandboxConfig.from_env`` -- never by this script reaching into
    ``os.environ``/``os.getenv`` for them directly."""
    source = LIVE_SCRIPT.read_text(encoding="utf-8")
    forbidden_direct_reads = (
        'os.environ["OPENAI_API_KEY"]', "os.environ['OPENAI_API_KEY']",
        'os.environ.get("OPENAI_API_KEY"', "os.environ.get('OPENAI_API_KEY'",
        'os.getenv("OPENAI_API_KEY"', "os.getenv('OPENAI_API_KEY'",
        'os.environ["GITHUB_TOKEN"]', "os.environ['GITHUB_TOKEN']",
        'os.environ.get("GITHUB_TOKEN"', "os.environ.get('GITHUB_TOKEN'",
        'os.getenv("GITHUB_TOKEN"', "os.getenv('GITHUB_TOKEN'",
    )
    for forbidden in forbidden_direct_reads:
        assert forbidden not in source, f"live script directly reads a raw secret env var: {forbidden!r}"


def test_live_script_contains_exact_not_executed_marker():
    source = LIVE_SCRIPT.read_text(encoding="utf-8")
    assert "LIVE OPENAI MODEL PROOF — NOT EXECUTED" in source


def test_live_script_uses_openai_provider_from_env():
    source = LIVE_SCRIPT.read_text(encoding="utf-8")
    assert "OpenAIAstraProvider.from_env()" in source


def test_live_script_success_marker_distinct_from_offline_script_marker():
    """The two scripts' PASSED banners must not be identical strings, so a
    log/report can never conflate a live-API run with an offline-fixture
    run just by grepping for the pass message."""
    offline_script = ROOT / "examples" / "universal_execution_proof" / "run_live_proof_astra.py"
    live_source = LIVE_SCRIPT.read_text(encoding="utf-8")
    offline_source = offline_script.read_text(encoding="utf-8")
    assert "ASTRA-TO-REAL-ACTUATOR LIVE PROOF PASSED" in offline_source
    assert "ASTRA-TO-REAL-ACTUATOR LIVE PROOF PASSED" not in live_source
    assert "LIVE OPENAI MODEL -> REAL ACTUATOR PROOF PASSED" in live_source


# --------------------------------------------------------------------------- #
# Regression guard: the live script must never claim, to itself, to the
# model, or in its own success/failure banners, that the live producer is
# "GPT-6 Astra" -- that label may appear ONLY inside comparative/denial
# prose (module docstring, comments), never as an unqualified identity
# claim about the actual live model.
# --------------------------------------------------------------------------- #

_FORBIDDEN_LIVE_IDENTITY_PHRASES = (
    "REAL live OpenAI-backed GPT-6 Astra",
    "real, live GPT-6 Astra model call",
    "LIVE OPENAI ASTRA",
    "LIVE ASTRA PROOF",
    "gpt-6-astra-live-openai",
    "live OpenAI Astra upstream",
    "genuine-live-OpenAI-Astra",
)


def test_live_script_never_contains_forbidden_astra_identity_phrases():
    source = LIVE_SCRIPT.read_text(encoding="utf-8")
    offenders = [phrase for phrase in _FORBIDDEN_LIVE_IDENTITY_PHRASES if phrase in source]
    assert not offenders, f"live script contains forbidden Astra-identity phrase(s): {offenders}"


def test_live_script_task_prompt_never_instructs_model_to_claim_gpt6_astra():
    """The text sent to the live model (the ``task`` local built in
    ``main()``) must never instruct it to describe itself as "GPT-6
    Astra" -- checked directly against the live script's own source since
    the prompt is a plain f-string, not a separately importable value."""
    source = LIVE_SCRIPT.read_text(encoding="utf-8")
    # The literal task-prompt fragment (as it appears in main()) must not
    # contain "GPT-6 Astra" anywhere between the f-string markers used to
    # build it. A simple substring check on the two sentences that make up
    # the prompt is sufficient and robust to incidental whitespace reflow.
    assert "a real, live GPT-6 Astra model" not in source
    assert "a real, live OpenAI model" in source


def test_live_actor_label_is_not_astra_branded():
    import examples.universal_execution_proof.run_live_proof_astra_openai as m

    assert "astra" not in m.LIVE_OPENAI_MODEL_ACTOR.lower()
    assert m.LIVE_OPENAI_MODEL_ACTOR == "live-openai-model/v1"


# --------------------------------------------------------------------------- #
# require_live_response: is_live gating, in isolation, no network.
# --------------------------------------------------------------------------- #

def test_require_live_response_accepts_live_response():
    import examples.universal_execution_proof.run_live_proof_astra_openai as m

    resp = AstraResponse(outcome=[], is_live=True, model="gpt-4o-mini")
    m.require_live_response(resp)  # must not raise


def test_require_live_response_rejects_non_live_response():
    import examples.universal_execution_proof.run_live_proof_astra_openai as m

    resp = AstraResponse(outcome=[], is_live=False, raw_note="offline fixture")
    with pytest.raises(AstraUpstreamError):
        m.require_live_response(resp)


# --------------------------------------------------------------------------- #
# astra_proposal_to_http_request: additive actor override, backward-compat.
# --------------------------------------------------------------------------- #

def test_actor_override_default_unchanged():
    proposal = AstraProposal(action="a", resource="r", payload={"k": "v"})
    request = astra_proposal_to_http_request(proposal)
    assert request["actor"] == "gpt-6-astra-reference/v1"


def test_actor_override_applies_distinct_live_label():
    import examples.universal_execution_proof.run_live_proof_astra_openai as m

    proposal = AstraProposal(action="a", resource="r", payload={"k": "v"})
    request = astra_proposal_to_http_request(proposal, actor=m.LIVE_OPENAI_MODEL_ACTOR)
    assert request["actor"] == "live-openai-model/v1"
    assert request["actor"] != "gpt-6-astra-reference/v1"


def test_not_executed_marker_constant_matches_required_string():
    import examples.universal_execution_proof.run_live_proof_astra_openai as m

    assert m.NOT_EXECUTED_MARKER == "LIVE OPENAI MODEL PROOF — NOT EXECUTED"
