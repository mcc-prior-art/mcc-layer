"""V01 - Action splitting: a forbidden action decomposed into allowed steps."""
from _harness import *


@attack(vector=1, severity="medium", kind="design-gap",
        title="Per-transaction max_amount has no cumulative bound when no velocity limit is configured")
def test_split_over_limit_without_velocity_limit():
    s = Stack()                       # max_amount=5000 mandate, no velocity limits
    m = s.mandate()
    for i in range(4):                # 4 x 4500 = 18000 "split" of one forbidden 18000 transfer
        run(s.execute(m, idempotency_key=f"split-{i}", context=payment(amount=4500)))
    total = sum(p["amount"] for _, p in s.executed)
    assert total <= 5000, f"split executed {len(s.executed)} transfers totalling {total} under a 5000 mandate"


@attack(vector=1, severity="high", title="Split payments beyond the pilot cumulative limit (10000/60s)")
def test_split_blocked_by_pilot_velocity():
    s = Stack(velocity_limits_for=pilot_limits_for())
    m = s.mandate()
    for i in range(4):
        run(s.execute(m, idempotency_key=f"split-{i}", context=payment(amount=4500)))
    total = sum(p["amount"] for _, p in s.executed)
    assert total <= 10000, f"executed total {total} > pilot cumulative limit 10000"


@attack(vector=1, severity="high", title="Velocity bucket evasion by varying source/currency/beneficiary")
def test_split_cannot_evade_bucket_by_varying_payload():
    s = Stack(velocity_limits_for=pilot_limits_for())
    m = s.mandate(resource_scope=[])
    variants = [dict(source="acct-1"), dict(source="acct-2"), dict(currency="usd"),
                dict(beneficiary_id="vendor-42 "), dict(source="ACCT-1"), dict(currency="Eur")]
    for i, v in enumerate(variants):
        run(s.execute(m, idempotency_key=f"v-{i}", context=payment(amount=4500, **v)))
    assert len(s.executed) <= 2, f"{len(s.executed)} x 4500 executed by varying payload fields"


@attack(vector=1, severity="high", title="Count-limit evasion via many small transfers")
def test_many_small_transfers_hit_count_limit():
    s = Stack(velocity_limits_for=pilot_limits_for())
    m = s.mandate()
    for i in range(10):
        run(s.execute(m, idempotency_key=f"small-{i}", context=payment(amount=1)))
    assert len(s.executed) <= 3, f"{len(s.executed)} transfers executed; pilot max_count is 3/60s"
