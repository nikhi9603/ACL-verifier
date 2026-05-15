# CyberRange ACL Verifier

Automated verification engine for **Headscale ACL policies** in the CySTAR multi-tenant cybersecurity lab platform at IIT Madras. Catches ACL misconfigurations before they become security incidents — without manually spot-checking rules or pushing test policies to a live server.

---

## The Problem

In a multi-tenant cyber range, every student gets an isolated `/24` subnet and a dedicated subnet router. A single misconfigured ACL rule — a student pointing to another tenant's subnet, a `/16` instead of a `/24`, a missing rule — can silently break isolation or deny a student access to their own lab. With N tenants, exhaustive network probing requires O(N²·H²) probes (where H = 254 usable IPs per subnet). At N=255 that's over 4 billion probes.

This tool verifies the same invariants in **6N probes** in the best case.

---

## How it Works

Verification runs in three stages, each catching a different class of violation.

### Stage 0 — Static Policy Check

Structural diff of the ACL against the database. No network access, no SSH. Catches:

| Violation              | Description                                                    |
| ---------------------- | -------------------------------------------------------------- |
| `WRONG_SUBNET`         | User's rule points to a subnet not assigned to them            |
| `OVERLY_BROAD_RULE`    | Rule covers more than the user's `/24`                         |
| `PRIVILEGE_ESCALATION` | Non-admin rule overlaps the management subnet (`10.20.0.0/16`) |
| `MISSING_RULE`         | User has a subnet in DB but no ACL rule                        |
| `DUPLICATE_RULES`      | User has more than one ACL rule                                |
| `ORPHAN_RULE`          | ACL rule references a user not in the DB                       |

`WRONG_SUBNET` in particular is invisible to dynamic probing — a user pointing to a non-existent subnet shows zero peers in Phase 1, which looks clean. The static checker catches it before a single SSH call is made.

### Stage 1 — Phase 1 Sweep (O(N))

Each router SSHes into its subnet router and runs `tailscale status`. If a peer that should be absent appears in the output, that's an isolation leak. One SSH call per router, results cached.

**Why `tailscale status` and not ping?** Headscale ACLs control WireGuard peer advertisement — nodes that aren't permitted to communicate are never sent each other's public key. They simply don't appear as peers. Checking peer visibility is the correct, unambiguous probe mechanism.

### Stage 2 — Phase 2 Localisation (O(k·N))

Only triggered for users who failed Phase 1 or were flagged by the static checker. Tests all N-1 other subnets to identify exactly which boundary is violated. k is typically 0 in a healthy system.

**Probe count summary:**

| Scenario                        | Probes        |
| ------------------------------- | ------------- |
| Best case (no violations)       | 6N            |
| Typical (k violations, k ≪ N)   | 6N + 2k(N-1) |
| Worst case (all users violated) | 4N + 2N²      |
| Naive exhaustive baseline       | 254² × N(N-1) |
| Reduction at N=255(best case)   | ~2.7 million× |

![Scaling Evaluation](evaluation/scaling_evaluation.png)

---

## Project Structure

```text
.
├── acl_generator/
│   └── generator.py          # Generates correct Headscale huJSON policy from DB
├── evaluation/
│   └── scaling_evaluation.py # Probe count vs N plots across 7 scales
├── models/
│   ├── db_interface.py       # Abstract DB interface + get_user_subnet_map()
│   ├── db_models.py          # User, SubnetAllocation, LabDeployment dataclasses
│   └── policy.py             # HeadscalePolicy, ACLRule dataclasses
├── probe_executor/
│   ├── mock_executor.py      # Fault-injection simulator (no network)
│   ├── policy_executor.py    # Oracle: evaluates probes against ACL semantics
│   └── two_phase_pipeline.py # Orchestrates all three stages end-to-end
├── probe_generator/
│   └── two_phase_generator.py # Generates probes from DB ground truth (never from ACL)
├── static_policy_checker/
│   └── policy_checker.py     # Stage 0: structural ACL diff
├── synthetic_data/
│   └── generator.py          # In-memory DB for testing (no Postgres needed)
├── tests/
│   ├── conftest.py           # Pytest fixtures
│   ├── helpers.py            # Shared test utilities
│   ├── test_oracle.py        # Oracle ACL semantics tests
│   ├── test_probe_generator.py # Probe count and structure invariants
│   └── test_static_checker.py  # All 6 violation types + edge cases
├── real_executor.py          # Live verifier: SSH into real AWS routers
└── pyproject.toml
```

---

## Architecture Decisions

**Probes are always generated from DB ground truth, never from the ACL.** The `TwoPhaseProbeGenerator` takes only `user_subnet_map` (derived from the database). A buggy ACL cannot influence which probes are generated or what they expect to see. This is the core correctness invariant.

**The oracle (`PolicyAwareExecutor`) and the real executor are independent.** The oracle evaluates probes against the ACL file in pure Python, modelling Headscale's deny-by-default first-match semantics. The real executor checks live peer visibility via SSH. Comparing them catches divergence between what the ACL says and what Headscale actually enforces.

**SSH errors are quarantined.** A router that can't be reached produces `ERROR` outcomes, not `FAIL`. Errors are reported separately and never trigger Phase 2 escalation or inflate violation counts. If a router was flagged by the static checker, Phase 2 still runs for it when the SSH error clears.

**Note on oracle mismatches with overly-permissive ACLs:** Headscale's peer advertisement model is stricter than ACL semantics alone. Even with a `/16` rule, peers may not be mutually visible unless both sides have matching rules. Oracle mismatches on such policies are expected and meaningful — they reflect real Headscale behaviour, not bugs in the verifier.

---

## Getting Started

### Prerequisites

- Python 3.12+
- Access to a running Headscale server
- SSH key for the subnet router instances
- PostgreSQL connection string for the cyberrange DB

### Installation

```bash
git clone https://github.com/umadhatri/ACL-verifier.git
cd ACL-verifier
python3 -m venv env
source env/bin/activate
pip install psycopg2-binary requests
```

### Run the test suite (no network required)

```bash
PYTHONPATH=. pytest
# 68 tests, ~0.05s
```

### Run against live infrastructure

```bash
PYTHONPATH=. python3 real_executor.py \
  --conn-str      "postgresql://user:pass@localhost/cyberrange" \
  --ssh-key       "/path/to/SubnetRouter.pem" \
  --acl-file      "/path/to/policy.hujson" \
  --headscale-url "https://your-headscale-server" \
  --headscale-api-key "your-api-key"
```

Add `--phase2-all` to force Phase 2 for all users regardless of Phase 1 results (useful for small N or debugging).

Exit code 0 = clean. Exit code 1 = violations found.

### Run the mock pipeline (synthetic DB, no network)

```bash
PYTHONPATH=. python3 probe_executor/two_phase_pipeline.py
```

### Run scaling evaluation

```bash
PYTHONPATH=. python3 evaluation/scaling_evaluation.py
# Generates scaling_evaluation.png
```

---

## Sample Output

### Clean policy

```
STAGE 0: Static policy check (structural, no SSH)
=================================================================
✓ No structural violations found.

STAGE 2: Phase 1 canary sweep (O(N) isolation check)
  SSH [user-abc@13.207.4.92] tailscale status ... ok — 0 peer(s) visible
  SSH [user-def@52.66.212.88] tailscale status ... ok — 0 peer(s) visible
  SSH [user-ghi@13.235.248.76] tailscale status ... ok — 0 peer(s) visible

→ No leaks detected. Phase 2 not needed.

FINAL SUMMARY
Static violations:     0
Total probes run:      9
Dynamic violations:    0
Oracle mismatches:     0
✓ ACL correctly enforces peer isolation. No violations found.
```

### Misconfigured policy (WRONG_SUBNET + PRIVILEGE_ESCALATION)

```
STAGE 0: Static policy check (structural, no SSH)
=================================================================
🚨 CRITICAL — WRONG_SUBNET (2)
   user-abc: Rule points to 10.20.1.0/24 but DB assigns 10.20.3.0/24
   user-def: Rule points to 10.20.1.0/24 but DB assigns 10.20.2.0/24

→ 2 user(s) escalated to Phase 2: ['user-abc', 'user-def']

FINAL SUMMARY
Static violations:     2
🚨 2 structural violation(s) found by static checker.
   Review ACL rules for the affected users.
```

---

## Security Invariants Enforced

1. **Tenant isolation** — no student can reach another student's subnet
2. **Management cloaking** — non-admin roles cannot access `10.20.0.0/16`
3. **Subnet ownership** — each user's ACL rule points to their own assigned `/24`
4. **Rule completeness** — every active user with a subnet allocation has a rule
5. **No orphan rules** — every ACL rule references an active DB user

---

## Contributing

1. Branch from `main`
2. Run `PYTHONPATH=. pytest` — all 68 tests must pass
3. For changes to probe generation or the static checker, add tests covering the new behaviour
4. Open a pull request for review
