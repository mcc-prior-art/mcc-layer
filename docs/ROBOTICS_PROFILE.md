# Robotics Profile — Domain Neutrality, Demonstrated Twice

The robotics profile is the *second* non-payment domain (after infrastructure).
Its only purpose is to show, again, that MCC-Core's universal core is
domain-neutral: robotics actuation is expressed entirely through a profile, and
the token, gate, authority, audit, and replay semantics are unchanged. The core
gains **no** robotics vocabulary.

Like infrastructure, robotics needs no new constraint *kinds* — its safety
limits ride the universal convention (`allowed_*` allow-lists, `max_*` ceilings).

## Actions

`move_to_zone`, `pick_object`, `release_object`, `enter_restricted_area`,
`exceed_force_limit` — routed to `RoboticsProfile` by
`ProfileRegistry.default_pilot()`.

## Canonical payload

| Field | Meaning |
|---|---|
| `robot` | the resource actuating (also `resource_id`) |
| `zone` | where the action happens (normalised lower-case) |
| `object_id` | for pick/release |
| `force` | applied force (normalised to float) |

`canonical_payload` requires `robot` + `zone` (else `ProfileError`). The whole
payload is covered by `payload_hash`: substituting `robot` or `zone` after
signing is a `PAYLOAD_HASH_MISMATCH` denial.

## Token binding

`auth_claims` surfaces `{robot, zone, object_id, force}` as signature-covered
claims; `resource_id` is set to `robot`. Universal binding (actor, resource,
transaction, action_hash, policy_hash, mandate_id) is unchanged.

## Safety constraints (universal convention)

```
constraints: { "allowed_zone": ["zone-a", "zone-b"], "max_force": 50 }
```

* `force` over `max_force` → **CONSTRAIN**, force clamped to the ceiling.
* `zone` not in `allowed_zone` → **DENY** (a restricted zone is simply one not
  on the allow-list; there is no safe rewrite). This is how
  `enter_restricted_area` is governed — by the zone, not by special-case code.

Evaluated by the same `_constraint_violations` / `apply_constraints` used for
payments and infrastructure — no robotics-specific evaluation code in core.

## Velocity

`RoboticsProfile.velocity_descriptor` aggregates by `actor + robot + zone`,
treats `zone` as the destination, and contributes `force` (when numeric) — so
"no more than N moves per robot per window" or a cumulative-force ceiling are
expressible with the existing `VelocityLimit`.

## End-to-end path

`tests/test_robotics_profile.py::test_full_robotics_execution_through_coordinator`
drives a `move_to_zone` through the identical pipeline as payments and infra:

```
signed mandate (action_scope=[move_to_zone], allowed_zone/max_force)
  → MandateAuthority (ALLOW)
  → decision token (RoboticsProfile canonical payload + auth_claims + mandate_id)
  → ExecutionGate (signature, binding, nonce)
  → EnforcementCoordinator (idempotency, velocity, audit-before-actuation)
  → execute → finalize
```

## What stays universal

actor binding · resource binding · action_hash · scope · authority · policy_hash
· replay protection · constraints · auditability · execution-gate semantics —
none changed to add robotics. Three domains now (payments, infrastructure,
robotics) share one core; a fourth (e.g. procurement) would be one more profile.
