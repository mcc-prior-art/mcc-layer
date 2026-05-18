package mcc

import rego.v1

default decision := {
  "decision": "DENY",
  "reason": "deny-by-default",
  "constraints": {},
  "policy_ref": "mcc.rego/default"
}

# -------------------------
# Payments
# -------------------------

decision := {
  "decision": "ALLOW",
  "reason": "payment within autonomous approval threshold",
  "constraints": {
    "max_amount": 5000
  },
  "policy_ref": "mcc.rego/send_payment/allow"
} if {
  input.intent == "send_payment"
  amount := input.args.amount
  amount <= 5000
}

decision := {
  "decision": "ESCALATE",
  "reason": "payment requires human approval",
  "constraints": {
    "required_approval": "finance_controller",
    "max_amount": 10000
  },
  "policy_ref": "mcc.rego/send_payment/escalate"
} if {
  input.intent == "send_payment"
  amount := input.args.amount
  amount > 5000
  amount <= 10000
}

decision := {
  "decision": "DENY",
  "reason": "payment amount exceeds autonomous and escalation threshold",
  "constraints": {},
  "policy_ref": "mcc.rego/send_payment/deny"
} if {
  input.intent == "send_payment"
  input.args.amount > 10000
}

# -------------------------
# User / data operations
# -------------------------

decision := {
  "decision": "ESCALATE",
  "reason": "user deletion requires privileged approval",
  "constraints": {
    "required_approval": "security_admin"
  },
  "policy_ref": "mcc.rego/delete_user/escalate"
} if {
  input.intent == "delete_user"
}

decision := {
  "decision": "DENY",
  "reason": "destructive production database operation denied",
  "constraints": {},
  "policy_ref": "mcc.rego/delete_database/deny"
} if {
  input.intent == "delete_database"
}

# -------------------------
# Email / communication
# -------------------------

decision := {
  "decision": "ALLOW",
  "reason": "email recipient count within approved autonomous scope",
  "constraints": {
    "max_recipients": 10
  },
  "policy_ref": "mcc.rego/send_email/allow"
} if {
  input.intent == "send_email"
  recipients := input.args.recipients
  count(recipients) <= 10
}

decision := {
  "decision": "ESCALATE",
  "reason": "bulk email requires human approval",
  "constraints": {
    "required_approval": "communications_owner"
  },
  "policy_ref": "mcc.rego/send_email/escalate"
} if {
  input.intent == "send_email"
  recipients := input.args.recipients
  count(recipients) > 10
}

# -------------------------
# Shell / code execution
# -------------------------

decision := {
  "decision": "CONSTRAIN",
  "reason": "shell execution allowed only in sandbox with constrained command scope",
  "constraints": {
    "environment": "sandbox",
    "deny_patterns": ["rm -rf", "curl http", "wget http", "nc ", "ssh "],
    "max_runtime_seconds": 30
  },
  "policy_ref": "mcc.rego/execute_bash/constrain"
} if {
  input.intent == "execute_bash"
  input.args.environment == "sandbox"
}

decision := {
  "decision": "DENY",
  "reason": "shell execution outside sandbox denied",
  "constraints": {},
  "policy_ref": "mcc.rego/execute_bash/deny"
} if {
  input.intent == "execute_bash"
  not input.args.environment == "sandbox"
}

# -------------------------
# Multi-agent orchestration
# -------------------------

decision := {
  "decision": "ESCALATE",
  "reason": "high-impact multi-agent orchestration requires supervisory approval",
  "constraints": {
    "required_approval": "system_owner"
  },
  "policy_ref": "mcc.rego/orchestrate_agents/escalate"
} if {
  input.intent == "orchestrate_agents"
}
