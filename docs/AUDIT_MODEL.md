# MCC-Core Audit Model

## Principle

MCC-Core follows audit-before-actuation.

Execution attempts are recorded before the actuator, external tool, API, workflow, or operational system is invoked.

---

## Audit Flow

1. Verify token.
2. Append `EXECUTION_ATTEMPT`.
3. If rejected, append `EXECUTION_REJECTED`.
4. If allowed, call actuator or execution surface.
5. Append `EXECUTION_SUCCEEDED`, `EXECUTION_FAILED`, or `EXECUTION_EXCEPTION`.

---

## Example Sequences

```text
EXECUTION_ATTEMPT
EXECUTION_SUCCEEDED
```

```text
EXECUTION_ATTEMPT
EXECUTION_REJECTED
```

```text
EXECUTION_ATTEMPT
EXECUTION_FAILED
```

```text
EXECUTION_ATTEMPT
EXECUTION_EXCEPTION
```

---

## Append-Only Rule

Existing audit entries are never mutated.

Corrections and finalization events must be appended as new entries.

**Audit before actuation. Always.**
