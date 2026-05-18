# MCC-Core Use Cases

## Agent Tool-Use Gateway

MCC-Core can serve as the execution gate before agent tools.

Example actions:

```text
send_email
call_api
update_database
create_payment
execute_bash
delete_file
orchestrate_agents
```

Example policy behavior:

| Action | MCC Outcome |
|---|---|
| `send_email` | ALLOW if scope and recipient policy match |
| `create_payment` | ESCALATE above threshold |
| `delete_file` | DENY in production unless explicitly authorized |
| `execute_bash` | CONSTRAIN or DENY depending on context |
| `orchestrate_agents` | ESCALATE for high-impact multi-agent actions |

Agent frameworks can plan actions.

MCC-Core decides whether those actions are authorized to execute.

---

## Cloud / Infrastructure Profile

Example high-risk action:

```json
{
  "subject": "agent/devops-worker",
  "action": "delete_database",
  "payload": {
    "database": "production-main",
    "region": "us-east-1"
  },
  "context": {
    "environment": "production",
    "risk_level": "critical"
  }
}
```

Possible MCC-Core decision:

```json
{
  "outcome": "DENY",
  "reason": "Destructive production action is not authorized for autonomous execution"
}
```

Alternative decision:

```json
{
  "outcome": "ESCALATE",
  "reason": "Two-key approval required for destructive infrastructure operation"
}
```

---

## Robotics / MCC-R Profile

MCC-R applies MCC-Core principles to robotics and physical AI.

A physical action may require:

- robot identity
- device trust
- operator authority
- policy match
- safety constraints
- action hash binding
- physical-zone context
- proximity context
- signed decision token
- valid nonce
- audit-before-actuation

Example controlled action:

```json
{
  "subject": "robot/arm-01",
  "action": "move",
  "payload": {
    "zone": "A3",
    "speed_mps": 0.3,
    "force_n": 5
  },
  "constraints": {
    "allowed_zone": "A3",
    "max_speed_mps": 0.4,
    "max_force_n": 10
  }
}
```

If the robot attempts to exceed the approved scope, the gate denies execution.

**No valid token — no actuation.**

MCC-R is not a certified functional safety system and does not replace E-stops, safety PLCs, or regulated safety mechanisms.

Functional safety systems govern hardware limits.

MCC-R governs AI action authority.
