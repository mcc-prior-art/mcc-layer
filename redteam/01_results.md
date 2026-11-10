# Red-team results — MCC-Core

Target commit `e600349` (branch `main`, merge of PR #128). No source file was modified.

Every test asserts the **secure** property, so *bypassed = yes* means the test failed: the
attack got through. A bypass is only claimed where the recording actuator was actually invoked
(or, for the audit and static checks, where the named verifier accepted the tampered input).

`kind` separates what the result means:

- **bypass** — the system did something its own policy/doctrine says it must not.
- **design-gap** — behaves as coded, but the behaviour leaves an authority hole worth a decision.
- **hardening** — not exploitable through the governed path today; removes a foot-gun or a second line of defence that is missing.
- **known-limitation** — already documented by the project; re-tested for exploitability only.

**175 attack cases run: 134 blocked, 41 got through.**

| kind | critical | high | medium | low |
|---|---|---|---|---|
| bypass | 4 | 14 | 4 | 0 |
| design-gap | 0 | 1 | 4 | 2 |
| hardening | 0 | 0 | 5 | 4 |
| known-limitation | 0 | 3 | 0 | 0 |

## Per vector

| # | vector | cases | blocked | got through |
|---|---|---|---|---|
| 1 | Action splitting | 4 | 3 | 1 |
| 2 | Parameter smuggling | 20 | 8 | 12 |
| 3 | Context forgery | 6 | 6 | 0 |
| 4 | Prompt injection | 19 | 19 | 0 |
| 5 | Multi-agent collusion | 3 | 1 | 2 |
| 6 | Race / TOCTOU | 5 | 5 | 0 |
| 7 | Replay | 6 | 4 | 2 |
| 8 | Policy gaps | 19 | 11 | 8 |
| 9 | Fail-open | 28 | 27 | 1 |
| 10 | Log tampering | 6 | 3 | 3 |
| 11 | Gate bypass | 5 | 3 | 2 |
| 12 | Canonicalization | 4 | 4 | 0 |
| 13 | Signature verification | 22 | 22 | 0 |
| 14 | Key exposure | 4 | 3 | 1 |
| 15 | Time | 6 | 4 | 2 |
| 16 | CONSTRAIN / ESCALATE | 7 | 4 | 3 |
| 17 | Crash recovery | 6 | 5 | 1 |
| 18 | Policy downgrade | 5 | 2 | 3 |

## Cases that got through

| vector | test | bypassed | severity | kind | evidence |
|---|---|---|---|---|---|
| 5 Multi-agent collusion | `test_v05_multi_agent_collusion.py::test_approval_obtained_by_a_executed_by_b_with_other_payload` | yes | critical | bypass | approved 100.0 -> vendor-42, executed [('send_payment', {'source': 'acct-1', 'beneficiary_id': 'attacker-acct', 'amount': 1000000.0, 'currency': 'EUR'})] (EXECUTED/ALLOW) |
| 16 CONSTRAIN / ESCALATE | `test_v16_constrain_escalate.py::test_approval_mandate_on_mandate_route_other_payload` | yes | critical | bypass | approved 100.0->vendor-42; executed {'source': 'acct-1', 'beneficiary_id': 'attacker-acct', 'amount': 1000000.0, 'currency': 'EUR'} (EXECUTED/ALLOW); payload_hash binding skipped |
| 16 CONSTRAIN / ESCALATE | `test_v16_constrain_escalate.py::test_approval_mandate_on_mandate_route_is_reusable` | yes | critical | bypass | single_use approval executed 5 times; approval state still APPROVED |
| 16 CONSTRAIN / ESCALATE | `test_v16_constrain_escalate.py::test_invalidated_approval_on_mandate_route` | yes | critical | bypass | operator-invalidated approval executed (EXECUTED); state=INVALIDATED |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_vs_max_amount[nan]` | yes | high | bypass | actuator received amount=[nan] under max_amount=5000 (status=EXECUTED, decision=ALLOW) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_vs_max_amount[nan-string]` | yes | high | bypass | actuator received amount=[nan] under max_amount=5000 (status=EXECUTED, decision=ALLOW) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_vs_max_amount[neg-inf]` | yes | high | bypass | actuator received amount=[-inf] under max_amount=5000 (status=EXECUTED, decision=ALLOW) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_vs_max_amount[negative]` | yes | high | bypass | actuator received amount=[-1000000.0] under max_amount=5000 (status=EXECUTED, decision=ALLOW) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_vs_max_amount[negative-string]` | yes | high | bypass | actuator received amount=[-1000000000.0] under max_amount=5000 (status=EXECUTED, decision=ALLOW) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_value_vs_generic_max_constraint[nan]` | yes | high | bypass | actuator received requested_discount_percent=[nan] under max 20 (EXECUTED) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_value_vs_generic_max_constraint[negative]` | yes | high | bypass | actuator received requested_discount_percent=[-50] under max 20 (EXECUTED) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_value_vs_generic_max_constraint[neg-inf]` | yes | high | bypass | actuator received requested_discount_percent=[-inf] under max 20 (EXECUTED) |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_constraint_key_fails_closed[max-amount]` | yes | high | bypass | constraint {'max-amount': 5000} ignored; executed amount=999999.0 (ALLOW) |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_constraint_key_fails_closed[amount_max]` | yes | high | bypass | constraint {'amount_max': 5000} ignored; executed amount=999999.0 (ALLOW) |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_constraint_key_fails_closed[MAX_amount]` | yes | high | bypass | constraint {'MAX_amount': 5000} ignored; executed amount=999999.0 (ALLOW) |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_constraint_key_fails_closed[denied_beneficiary]` | yes | high | bypass | constraint {'denied_beneficiary': ['vendor-42']} ignored; executed amount=999999.0 (ALLOW) |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_constraint_key_fails_closed[currency]` | yes | high | bypass | constraint {'currency': 'USD'} ignored; executed amount=999999.0 (ALLOW) |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_constraint_key_fails_closed[maxAmount]` | yes | high | bypass | constraint {'maxAmount': 5000} ignored; executed amount=999999.0 (ALLOW) |
| 5 Multi-agent collusion | `test_v05_multi_agent_collusion.py::test_mandate_requires_proof_of_possession` | yes | high | design-gap | second agent executed with first agent's mandate: [('send_payment', {'source': 'acct-1', 'beneficiary_id': 'intern-mule', 'amount': 100.0, 'currency': 'EUR'})] (EXECUTED) |
| 7 Replay | `test_v07_replay.py::test_token_replay_after_restart_memory_backend` | yes | high | known-limitation | token replayed after restart (executed); window = token TTL |
| 10 Log tampering | `test_v10_log_tampering.py::test_tail_truncation_detected_by_verify_chain` | yes | high | known-limitation | chain verifies after dropping the last 2 of 6 records (no external anchor in verify_chain) |
| 10 Log tampering | `test_v10_log_tampering.py::test_full_rewrite_detected_by_verify_chain` | yes | high | known-limitation | rewritten chain with one operation erased verifies (entries are hash-linked, not signed/anchored) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_action_name_is_not_a_url_injection_vector[dotdot]` | yes | medium | bypass | actuator dispatched action 'pay_x/../../admin/wipe'; upstream URL is built as base + '/' + action (EXECUTED) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_action_name_is_not_a_url_injection_vector[query]` | yes | medium | bypass | actuator dispatched action 'pay_x?admin=1'; upstream URL is built as base + '/' + action (EXECUTED) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_action_name_is_not_a_url_injection_vector[fragment]` | yes | medium | bypass | actuator dispatched action 'pay_x#frag'; upstream URL is built as base + '/' + action (EXECUTED) |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_action_name_is_not_a_url_injection_vector[newline]` | yes | medium | bypass | actuator dispatched action 'pay_\nX'; upstream URL is built as base + '/' + action (EXECUTED) |
| 1 Action splitting | `test_v01_action_splitting.py::test_split_over_limit_without_velocity_limit` | yes | medium | design-gap | split executed 4 transfers totalling 18000.0 under a 5000 mandate |
| 7 Replay | `test_v07_replay.py::test_gate_nonce_ttl_shorter_than_token_lifetime` | yes | medium | hardening | gate re-verified a used token after its nonce record expired |
| 10 Log tampering | `test_v10_log_tampering.py::test_pre_token_denials_are_audited` | yes | medium | hardening | 0 audit records for 2 denied execution attempts (probing is invisible in the chain) |
| 11 Gate bypass | `test_v11_gate_bypass.py::test_egress_executor_verifies_token_signature` | yes | medium | hardening | executor.execute() authorizes any dict {'decision':'ALLOW','action':<action>} - no signature check |
| 14 Key exposure | `test_v14_key_exposure.py::test_service_refuses_to_start_without_configured_signing_key` | yes | medium | hardening | main.py falls back to SigningKey.generate() (warning only) when MCC_SIGNING_KEY_PATH is unset |
| 15 Time | `test_v15_time.py::test_approval_ttl_is_capped` | yes | medium | design-gap | approval mandate valid for 3650 days (ttl_seconds is set by the requesting agent) |
| 17 Crash recovery | `test_v17_crash_recovery.py::test_crashed_operation_resent_under_new_key` | yes | medium | design-gap | same transaction_id dispatched twice (EXECUTED) while the first outcome is still UNKNOWN |
| 18 Policy downgrade | `test_v18_policy_downgrade.py::test_approval_policy_binding_is_not_caller_optional` | yes | medium | design-gap | approval mandate policy_hash=None (taken from the agent's request) |
| 18 Policy downgrade | `test_v18_policy_downgrade.py::test_policy_bundle_load_is_pinned` | yes | medium | hardening | main.py: PolicyBundle.from_file(path, policy_id) - a swapped policy file is accepted and its new hash signed into tokens |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_allowed_constraint_with_string_bound` | yes | low | hardening | currency 'R,U' accepted by substring match |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_empty_resource_scope_means_any_resource` | yes | low | design-gap | empty resource_scope acted as wildcard |
| 9 Fail-open | `test_v09_fail_open.py::test_null_currency_rejected` | yes | low | hardening | currency=None executed as 'NONE' |
| 11 Gate bypass | `test_v11_gate_bypass.py::test_gate_requires_action_and_payload_binding` | yes | low | hardening | gate verified a token without checking what is about to be executed |
| 15 Time | `test_v15_time.py::test_caller_cannot_supply_enforcement_time` | yes | low | hardening | hour-old expired token executed because the caller passed now=<past> |
| 18 Policy downgrade | `test_v18_policy_downgrade.py::test_unbound_mandate_survives_policy_rotation` | yes | low | design-gap | mandate with policy_hash=None accepted under the current policy (binding is optional) |

## Cases that were blocked

| vector | test | bypassed | severity | what was attempted |
|---|---|---|---|---|
| 1 Action splitting | `test_v01_action_splitting.py::test_split_blocked_by_pilot_velocity` | no | high | Split payments beyond the pilot cumulative limit (10000/60s) |
| 1 Action splitting | `test_v01_action_splitting.py::test_split_cannot_evade_bucket_by_varying_payload` | no | high | Velocity bucket evasion by varying source/currency/beneficiary |
| 1 Action splitting | `test_v01_action_splitting.py::test_many_small_transfers_hit_count_limit` | no | high | Count-limit evasion via many small transfers |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_with_pilot_velocity[nan]` | no | high | Non-finite / negative amount with pilot velocity limits configured |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_with_pilot_velocity[nan-string]` | no | high | Non-finite / negative amount with pilot velocity limits configured |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_with_pilot_velocity[neg-inf]` | no | high | Non-finite / negative amount with pilot velocity limits configured |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_with_pilot_velocity[negative]` | no | high | Non-finite / negative amount with pilot velocity limits configured |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_bad_amount_with_pilot_velocity[negative-string]` | no | high | Non-finite / negative amount with pilot velocity limits configured |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_over_limit_amount_is_clamped` | no | critical | Over-limit amount is clamped, original never executes |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_string_amount_on_generic_action_fails_closed` | no | high | Numeric-string amount on a generic action |
| 2 Parameter smuggling | `test_v02_parameter_smuggling.py::test_payload_cannot_carry_its_own_authority` | no | high | Extra payload keys cannot override verdict or constraints |
| 3 Context forgery | `test_v03_context_forgery.py::test_other_subjects_mandate_rejected` | no | critical | Mandate issued to another subject |
| 3 Context forgery | `test_v03_context_forgery.py::test_forged_mandate_with_trusted_kid` | no | critical | Mandate signed by an attacker key with a trusted kid label |
| 3 Context forgery | `test_v03_context_forgery.py::test_tampered_mandate_rejected` | no | critical | Tampered mandate (constraints / scope / expiry widened) |
| 3 Context forgery | `test_v03_context_forgery.py::test_forged_approval_mandate_rejected` | no | critical | Forged prior approval (self-minted approval mandate) |
| 3 Context forgery | `test_v03_context_forgery.py::test_resource_scope_enforced` | no | high | Resource outside mandate scope / omitted resource |
| 3 Context forgery | `test_v03_context_forgery.py::test_token_binding_mismatch_rejected` | no | high | Token minted for one actor/resource replayed with a different binding |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[0]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[1]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[2]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[3]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[4]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[5]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[6]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[7]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_payload_fields[8]` | no | high | Injected text in payload fields cannot lift a constraint |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[0]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[1]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[2]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[3]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[4]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[5]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[6]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[7]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_in_identity_fields[8]` | no | high | Injected text as action / resource / actor cannot widen scope |
| 4 Prompt injection | `test_v04_prompt_injection.py::test_injection_cannot_forge_audit_lines` | no | medium | Injected newline/JSON in fields cannot forge audit records |
| 5 Multi-agent collusion | `test_v05_multi_agent_collusion.py::test_token_for_a_cannot_be_enforced_for_b` | no | high | Decision token minted for agent A enforced on behalf of agent B |
| 6 Race / TOCTOU | `test_v06_toctou.py::test_concurrent_same_idempotency_key_executes_once` | no | critical | 25 concurrent executes with one idempotency key |
| 6 Race / TOCTOU | `test_v06_toctou.py::test_concurrent_token_replay_executes_once` | no | critical | 25 concurrent replays of one decision token |
| 6 Race / TOCTOU | `test_v06_toctou.py::test_revocation_between_check_and_execution` | no | high | Mandate revoked between authorization and actuation |
| 6 Race / TOCTOU | `test_v06_toctou.py::test_invalidate_races_approval_execute` | no | high | Approval invalidated while its execution is in flight |
| 6 Race / TOCTOU | `test_v06_toctou.py::test_concurrent_velocity_reservations` | no | medium | Concurrent velocity reservations cannot jointly exceed the limit |
| 7 Replay | `test_v07_replay.py::test_token_replay_same_instance` | no | critical | Straight replay of a used decision token |
| 7 Replay | `test_v07_replay.py::test_token_replay_other_payload` | no | critical | Replay of a used token with a different payload |
| 7 Replay | `test_v07_replay.py::test_enforcement_mode_refuses_memory_backends` | no | high | Enforcement mode refuses volatile replay state |
| 7 Replay | `test_v07_replay.py::test_coordinator_blocks_replay_even_if_nonce_slot_freed` | no | high | Same misconfiguration end-to-end: idempotency still blocks the re-execution |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_action_is_not_allowed_by_authority_model[wire_swift]` | no | critical | Action that no policy rule covers |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_action_is_not_allowed_by_authority_model[SEND_PAYMENT]` | no | critical | Action that no policy rule covers |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_action_is_not_allowed_by_authority_model[send_payment ]` | no | critical | Action that no policy rule covers |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_action_is_not_allowed_by_authority_model[]` | no | critical | Action that no policy rule covers |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_action_is_not_allowed_by_authority_model[delete_database]` | no | critical | Action that no policy rule covers |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_action_is_not_allowed_by_authority_model[medical_advice_request]` | no | critical | Action that no policy rule covers |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_unknown_action_is_not_allowed_by_authority_model[refund_request]` | no | critical | Action that no policy rule covers |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_action_outside_mandate_scope[wire_swift]` | no | critical | Action outside the mandate's action scope |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_action_outside_mandate_scope[send_payment2]` | no | critical | Action outside the mandate's action scope |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_action_outside_mandate_scope[SEND_PAYMENT]` | no | critical | Action outside the mandate's action scope |
| 8 Policy gaps | `test_v08_policy_gaps.py::test_action_outside_mandate_scope[send_paymen]` | no | critical | Action outside the mandate's action scope |
| 9 Fail-open | `test_v09_fail_open.py::test_nonce_backend_down` | no | critical | Nonce registry down |
| 9 Fail-open | `test_v09_fail_open.py::test_idempotency_backend_down` | no | critical | Idempotency registry down |
| 9 Fail-open | `test_v09_fail_open.py::test_velocity_backend_down` | no | critical | Velocity registry down |
| 9 Fail-open | `test_v09_fail_open.py::test_revocation_backend_down` | no | critical | Revocation registry down at actuation |
| 9 Fail-open | `test_v09_fail_open.py::test_audit_unwritable` | no | critical | Audit log unwritable (audit-before-actuation) |
| 9 Fail-open | `test_v09_fail_open.py::test_time_source_down` | no | critical | Trusted time source unavailable |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[0]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[1]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[2]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[3]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[4]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[5]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[6]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[7]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[8]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[9]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_mandate[10]` | no | critical | Malformed mandate objects |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_payload[0]` | no | high | Malformed payload field types |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_payload[1]` | no | high | Malformed payload field types |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_payload[2]` | no | high | Malformed payload field types |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_payload[3]` | no | high | Malformed payload field types |
| 9 Fail-open | `test_v09_fail_open.py::test_malformed_payload[4]` | no | high | Malformed payload field types |
| 9 Fail-open | `test_v09_fail_open.py::test_missing_operation_identity[0]` | no | high | Missing idempotency key / tenant |
| 9 Fail-open | `test_v09_fail_open.py::test_missing_operation_identity[1]` | no | high | Missing idempotency key / tenant |
| 9 Fail-open | `test_v09_fail_open.py::test_missing_operation_identity[2]` | no | high | Missing idempotency key / tenant |
| 9 Fail-open | `test_v09_fail_open.py::test_missing_operation_identity[3]` | no | high | Missing idempotency key / tenant |
| 9 Fail-open | `test_v09_fail_open.py::test_executor_crash_is_not_silently_retried` | no | high | Executor crash leaves the operation non-retryable |
| 10 Log tampering | `test_v10_log_tampering.py::test_edit_entry_detected` | no | high | In-place edit of a recorded entry |
| 10 Log tampering | `test_v10_log_tampering.py::test_delete_middle_entry_detected` | no | high | Delete / reorder an entry in the middle of the chain |
| 10 Log tampering | `test_v10_log_tampering.py::test_denied_attempts_are_audited` | no | medium | Blocked attempts are recorded, not just successes |
| 11 Gate bypass | `test_v11_gate_bypass.py::test_upstream_only_called_from_enforced_executor` | no | critical | GovernanceService reaches the upstream only inside coordinator.enforce |
| 11 Gate bypass | `test_v11_gate_bypass.py::test_gate_rejection_blocks_every_service_path` | no | critical | With the real gate trusting no key, no public execute_* path reaches the actuator |
| 11 Gate bypass | `test_v11_gate_bypass.py::test_no_unexpected_token_issuers` | no | high | No runtime module issues tokens or calls an actuator outside the governed path |
| 12 Canonicalization | `test_v12_canonicalization.py::test_no_hash_collisions_between_distinct_json_documents` | no | critical | Distinct JSON payloads never share a payload_hash |
| 12 Canonicalization | `test_v12_canonicalization.py::test_parser_differential_is_closed_by_reserialization` | no | critical | Key order / whitespace / duplicate keys cannot change what is signed vs executed |
| 12 Canonicalization | `test_v12_canonicalization.py::test_action_hash_lookalikes` | no | high | Action hash distinguishes look-alike action names |
| 12 Canonicalization | `test_v12_canonicalization.py::test_executed_payload_matches_signed_hash` | no | high | Executed payload is byte-identical to the signed payload |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[amount-claim]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[decision]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[exp]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[nonce]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[idempotency_key]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[tenant]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[mandate_id]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[kid-none]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[kid-unknown]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[kid-list]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[sig-empty]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[sig-missing]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[sig-zero]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[sig-list]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[alg-none]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_mutated_token_rejected[extra-claim]` | no | critical | Any change to a signed token invalidates it |
| 13 Signature verification | `test_v13_signature.py::test_token_signed_by_mandate_issuer_or_approver_key` | no | critical | Key confusion: token signed by a key trusted for another role |
| 13 Signature verification | `test_v13_signature.py::test_decision_token_is_not_a_mandate` | no | critical | Artifact confusion: a decision token presented as a mandate |
| 13 Signature verification | `test_v13_signature.py::test_revoked_or_disabled_issuer_key` | no | critical | Mandate signed by a revoked key / disabled issuer |
| 13 Signature verification | `test_v13_signature.py::test_signature_encoding_malleability_is_not_a_replay` | no | medium | Signature malleability cannot mint a second usable token |
| 13 Signature verification | `test_v13_signature.py::test_audience_and_policy_binding` | no | critical | Wrong audience / wrong policy hash |
| 13 Signature verification | `test_v13_signature.py::test_non_executable_verdicts` | no | critical | DENY / ESCALATE can never be turned into an executable token |
| 14 Key exposure | `test_v14_key_exposure.py::test_no_private_key_serialization_in_runtime` | no | critical | No runtime module serializes a private key |
| 14 Key exposure | `test_v14_key_exposure.py::test_agent_package_cannot_sign` | no | critical | Agent package holds no signing capability |
| 14 Key exposure | `test_v14_key_exposure.py::test_no_key_material_in_outputs` | no | critical | No key material in outcomes, tokens or the audit chain |
| 15 Time | `test_v15_time.py::test_mandate_validity_window` | no | critical | Expired / not-yet-valid mandate, including the exact boundary |
| 15 Time | `test_v15_time.py::test_token_exp_clamped_to_mandate_exp` | no | high | Token never outlives the mandate that justified it |
| 15 Time | `test_v15_time.py::test_expired_token_rejected` | no | critical | Expired decision token (boundary: now == exp) |
| 15 Time | `test_v15_time.py::test_future_or_malformed_window` | no | high | Token issued in the future (nbf) / with non-integer window |
| 16 CONSTRAIN / ESCALATE | `test_v16_constrain_escalate.py::test_constrain_executes_only_clamped_payload` | no | critical | CONSTRAIN: only the clamped payload reaches the actuator |
| 16 CONSTRAIN / ESCALATE | `test_v16_constrain_escalate.py::test_unapproved_escalation_never_executes` | no | critical | ESCALATE: pending / denied / expired approval never executes |
| 16 CONSTRAIN / ESCALATE | `test_v16_constrain_escalate.py::test_approval_route_binds_payload_and_is_single_use` | no | critical | Approval route: different payload / second use / after invalidation |
| 16 CONSTRAIN / ESCALATE | `test_v16_constrain_escalate.py::test_approval_request_constraints_do_not_widen` | no | high | Agent-supplied constraints on the approval request cannot widen the approved payload |
| 17 Crash recovery | `test_v17_crash_recovery.py::test_unknown_outcome_not_redispatched` | no | critical | Indeterminate (crashed) operation is not re-dispatched for the same key |
| 17 Crash recovery | `test_v17_crash_recovery.py::test_unknown_outcome_survives_gate_restart` | no | critical | Crash after dispatch + gate restart: same operation key still blocked |
| 17 Crash recovery | `test_v17_crash_recovery.py::test_idempotency_key_rebinding` | no | critical | Same idempotency key cannot be rebound to a different payload |
| 17 Crash recovery | `test_v17_crash_recovery.py::test_crashed_approval_execution_not_repeatable` | no | critical | Single-use approval is not re-executable after a crashed dispatch |
| 17 Crash recovery | `test_v17_crash_recovery.py::test_nothing_executable_after_deny` | no | critical | A denied request leaves nothing executable behind |
| 18 Policy downgrade | `test_v18_policy_downgrade.py::test_mandate_bound_to_old_policy_rejected` | no | critical | Mandate bound to an older policy hash |
| 18 Policy downgrade | `test_v18_policy_downgrade.py::test_token_from_old_policy_rejected` | no | critical | Decision token issued under an older policy hash |
