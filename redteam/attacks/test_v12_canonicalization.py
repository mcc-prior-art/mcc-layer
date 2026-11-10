"""V12 - Canonicalization: two different payloads producing the same signed hash."""
import itertools
import json

from _harness import *
from mcc_core.signing import hash_action, hash_payload

DOCS = [
    '{"amount":1}', '{"amount":1.0}', '{"amount":"1"}', '{"amount":true}', '{"amount":1e0}',
    '{"amount":0}', '{"amount":-0.0}', '{"amount":0.0}', '{"amount":null}', '{}',
    '{"a":{"b":1}}', '{"a.b":1}', '{"a":[1,2]}', '{"a":[2,1]}', '{"a":"1,2"}',
    '{"k":"é"}', '{"k":"e\\u0301"}', '{"k":"\\u00e9 "}', '{"k":"E"}', '{"k":"e"}',
    '{"k":"a\\u0000"}', '{"k":"a"}', '{"k":"\\ud83d\\ude00"}', '{"k":"\\\\ud83d"}',
    '{"x":1,"y":2}', '{"x":2,"y":1}', '{"x":"1\\",\\"y\\":\\"2"}',
    '{"n":10000000000000000}', '{"n":10000000000000001}', '{"n":1e16}',
    '{"amount":100,"amount ":999}', '{"amount":100}', '{"Amount":100}',
]


@attack(vector=12, severity="critical", title="Distinct JSON payloads never share a payload_hash")
def test_no_hash_collisions_between_distinct_json_documents():
    parsed = [json.loads(d) for d in DOCS]
    collisions = []
    for (i, a), (j, b) in itertools.combinations(enumerate(parsed), 2):
        if hash_payload(a) == hash_payload(b) and json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True):
            collisions.append((DOCS[i], DOCS[j]))
    assert collisions == [], f"collisions: {collisions}"


@attack(vector=12, severity="critical", title="Key order / whitespace / duplicate keys cannot change what is signed vs executed")
def test_parser_differential_is_closed_by_reserialization():
    s = Stack()
    raw = '{"source":"acct-1","beneficiary_id":"vendor-42","amount":100,"currency":"EUR","amount":999999}'
    ctx = json.loads(raw)                 # Python: last duplicate wins -> 999999
    run(s.execute(s.mandate(), idempotency_key="k", context=ctx))
    # whatever was authorized must be exactly what the actuator got, and within bounds
    assert [p["amount"] for _, p in s.executed] == [5000], f"executed {s.executed}"


@attack(vector=12, severity="high", title="Action hash distinguishes look-alike action names")
def test_action_hash_lookalikes():
    names = ["send_payment", "send_payment ", "Send_payment", "send​_payment", "sеnd_payment",
             "send_payment\x00", "send__payment"]
    assert len({hash_action(n) for n in names}) == len(names)


@attack(vector=12, severity="high", title="Executed payload is byte-identical to the signed payload")
def test_executed_payload_matches_signed_hash():
    s = Stack()
    toks = spy_tokens(s)
    for i, ctx in enumerate([payment(), payment(amount="42"), payment(currency="eur"),
                             payment(amount=9999), payment(extra={"nested": [1, {"a": None}]})]):
        run(s.execute(s.mandate(), idempotency_key=f"k-{i}", context=ctx))
    assert len(toks) == len(s.executed) == 5
    for tok, (_, sent) in zip(toks, s.executed):
        assert tok["payload_hash"] == hash_payload(sent), (tok["payload_hash"], sent)
