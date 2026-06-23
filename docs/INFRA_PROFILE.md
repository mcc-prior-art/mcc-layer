# Infrastructure Profile — Domain Neutrality, Demonstrated

The infrastructure profile exists to prove a claim: MCC-Core's universal core is
**domain-neutral**. A completely different domain — infra operations — is
expressed entirely through a profile, with the token, gate, authority, audit,
and replay semantics unchanged. The core gains *no* infrastructure vocabulary.

Infrastructure was chosen over robotics because it leaks the least: it needs no
new constraint *kinds*. Its limits ride the universal constraint convention
(`allowed_*` allow-lists, `max_*` ceilings) already used by payments.

## Actions

`restart_service`, `change_firewall_rule`, `deploy_release`, `scale_cluster`,
`rotate_secret` — all routed to `InfraProfile` by `ProfileRegistry.default_pilot()`.

## Canonical payload

Required, authorization-bearing fields for every infra action:

| Field | Meaning |
|---|---|
| `target` | the resource operated on (cluster, service, rule, secret) |
| `environment` | `prod` / `staging` / … (normalised to lower-case) |
| *action-specific* | e.g. `replicas` (scale_cluster), `change_ref` (audit reference) |

`canonical_payload` requires `target` + `environment` (else `ProfileError`) and
normalises `environment`. The whole payload is covered by `payload_hash`, so
substituting `target` or `environment` after signing is a `PAYLOAD_HASH_MISMATCH`
denial.

## Token binding

`auth_claims` surfaces `{target, environment, change_ref}` as signature-covered
claims; `resource_id` is set to `target`. The universal binding (actor, resource,
transaction, action_hash, policy_hash, mandate_id) is unchanged.

## Constraints (universal convention)

Infra limits are ordinary constraints on a mandate or authority policy:

```
constraints: { "allowed_environment": ["prod", "staging"], "max_replicas": 10 }
```

* `replicas` over `max_replicas` → **CONSTRAIN**, body clamped to the cap.
* `environment` not in `allowed_environment` → **DENY** (no safe rewrite).

These are evaluated by the same `_constraint_violations` / `apply_constraints`
used for payments — no infra-specific evaluation code in core.

## Velocity

`InfraProfile.velocity_descriptor` aggregates by `actor + target + environment`,
treats `target` as the destination, and contributes `replicas` (when numeric) to
cumulative ceilings — so "no more than N infra changes to this target per
window" is expressible with the existing `VelocityLimit`.

## End-to-end path

`tests/test_infra_profile.py::test_full_infra_execution_through_coordinator`
drives a `scale_cluster`:

```
signed mandate (action_scope=[scale_cluster], constraints) 
  → MandateAuthority (ALLOW)
  → decision token (InfraProfile canonical payload + auth_claims + mandate_id)
  → ExecutionGate (signature, binding, nonce)
  → EnforcementCoordinator (idempotency, velocity, audit-before-actuation)
  → execute → finalize
```

Identical pipeline to payments — only the profile differs.

## What stays universal

actor binding · resource binding · action_hash · scope · authority · policy_hash
· replay protection · constraints · auditability · execution-gate semantics.
None of these changed to add infrastructure. Adding a *fourth* domain (robotics:
`move_to_zone`, `pick_object`, `enter_restricted_area`, `exceed_force_limit`)
would be one more profile, no core change.
