# CyberRange ACL Verifier

A policy-driven verification engine for **Headscale/Tailscale** ACLs. This tool ensures that your software-defined network isolation matches your intended security posture through Automated Test Pattern Generation (ATPG).

## The Mission
In a multi-tenant Cyber Range environment, a single misconfigured ACL rule can leak sensitive management subnets to student environments. This project eliminates "manual spot-checking" by treating network policies as verifiable code.

* **Generates** Headscale-compatible huJSON policies from a source-of-truth database.
* **Synthesizes** a minimal set of network "probes" (Reachability vs. Isolation).
* **Simulates** policy enforcement to detect "False Allows" (Security Violations) and "False Denies" (Reachability Failures).

---

## Project Structure
```text
.
├── acl_generator
│   ├── generator.py
│   └── __init__.py
├── probe_executor
│   ├── __init__.py
│   ├── mock_executor.py
│   └── policy_executor.py
├── probe_generator
│   ├── generator.py
│   └── __init__.py
├── README.md
└── synthetic_data
    ├── generator.py
    └── __init__.py
```

---

## How it Works

### 1. Policy Generation
The `ACLGenerator` reads active users and their allocated subnets to create a **deny-by-default** policy.
* **Admins:** Full access to the Management Subnet (`10.20.0.0/16`).
* **Users:** Restricted to their specific `/24` subnet.

### 2. Formal Verification
The `PolicyAwareExecutor` models Headscale's forwarding semantics. It evaluates every probe against the policy using first-match logic:
* **Positive Probes:** Verifies that students *can* reach their own labs.
* **Negative Probes:** Verifies that students *cannot* reach other students or the management core.

---

## Getting Started

### Prerequisites
* Python 3.12+
* Virtual Environment (recommended)

### Installation
```bash
git clone https://github.com/umadhatri/ACL-verifier.git
cd ACL-verifier
python3 -m venv env
source env/bin/bin/activate  # On Windows: .\env\Scripts\activate
```

### Running the Verifier
You can run the integrated test suite to see the verifier catch intentional faults:
```bash
PYTHONPATH=. python3 probe_executor/policy_executor.py
```

---

## Sample Output
When a violation is detected (e.g., a student gains access to the management subnet), the reporter flags it immediately:

```text
🚨 CRITICAL — Isolation violations (1):
   Probes that should be DENIED were ALLOWED by the ACL.
   ✗ FAIL | expected=DENY observed=ALLOW [matched rule 5] | isolation: student2 -> 10.20.0.0/16
```

---

## Security Invariants
This tool enforces the following invariants:
1. **Student Isolation:** No student-to-student traffic.
2. **Management Cloaking:** Management subnets are unreachable by non-admin roles.
3. **Explicit Tagging:** All router traffic must be tagged with `tag:router`.

---

## Contributing
1. Open a Feature Branch.
2. Ensure `policy_executor` passes with 0 violations.
3. Open a Pull Request for review.