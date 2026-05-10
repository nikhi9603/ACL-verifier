"""
Real Executor — Live ACL Verification via `tailscale status` peer visibility.

Reads running deployments from the real Postgres DB, parses the live
Headscale ACL policy file, generates two-phase probes, and executes
them by SSHing into each tenant's subnet router and checking whether
the target peer appears in `tailscale status`.

Why peer visibility, not ping:
  Headscale ACLs control WireGuard peer advertisement — nodes that a
  user is not permitted to reach are simply never sent their WireGuard
  public key. They are absent from `tailscale status` entirely. Pinging
  a Tailscale IP that was never advertised goes nowhere and produces an
  ambiguous timeout. Checking peer presence is the correct, unambiguous
  mechanism.

Probe semantics:
  Positive probe  (router → itself):     always PASS — a node always
                                          sees itself as the first entry.
                                          These are generated but verified
                                          cheaply without a real SSH call.
  Negative probe  (router A → router B): PASS if B is ABSENT from A's
                                          `tailscale status`; FAIL if B
                                          is PRESENT (isolation leak).

`tailscale status` line format (observed on live routers):
  <tailscale_ip>  <hostname>  <headscale_username>@  <os>  <status>

The headscale_username in the output matches the DB column exactly
(e.g. user-6360f798-2fdb-4c8f-a671-12cb35fcc3dd), just with a trailing @.

Usage:
    PYTHONPATH=. python3 real_executor.py \\
        --conn-str          "postgresql://user:pass@localhost/cyberrange" \\
        --ssh-key           "/path/to/SubnetRouter.pem" \\
        --acl-file          "/path/to/policy.hujson" \\
        --headscale-url     "https://sentinel.dedyn.io" \\
        --headscale-api-key "your-api-key-here"

    # Force Phase 2 for all users regardless of Phase 1 results (small N):
    PYTHONPATH=. python3 real_executor.py ... --phase2-all
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import requests
import psycopg2
import psycopg2.extras

from models.db_models import User, SubnetAllocation, UserRole
from models.db_interface import DatabaseInterface
from models.policy import HeadscalePolicy, ACLRule
from probe_generator.two_phase_generator import TwoPhaseProbeGenerator, Probe
from probe_executor.policy_executor import PolicyAwareExecutor, ViolationReporter, ProbeResult
from static_policy_checker.policy_checker import StaticPolicyChecker
# ProbeResult is imported from policy_executor (not redefined here) so that
# oracle comparison uses the same enum class as the real executor.
# Defining a second ProbeResult locally would make `real.result != ora.result`
# always True — two enum instances with the same name are not equal if they
# come from different enum classes.


class PeerVisibilityResult(Enum):
    """
    Three-valued result for peer-visibility probes.

    PASS  — observed peer visibility matches expected (correct ACL behaviour)
    FAIL  — observed peer visibility mismatches expected (real ACL violation)
    ERROR — SSH failed; result is indeterminate (infrastructure problem, not ACL)

    ERROR is kept separate from FAIL so that SSH timeouts/connection failures
    never trigger Phase 2 escalation or appear in the violation count.
    """
    PASS  = "PASS"
    FAIL  = "FAIL"
    ERROR = "ERROR"


@dataclass
class PeerVisibilityOutcome:
    """
    Result of a single peer-visibility probe.

    observed_visible: True  → target peer appeared in `tailscale status`
                     False → target peer was absent (or SSH failed)
    result:          PASS  → observed_visible matches probe.expected
                     FAIL  → ACL violation (isolation leak)
                     ERROR → SSH failure; indeterminate, not an ACL violation
    """
    probe: Probe
    observed_visible: bool
    result: PeerVisibilityResult
    error: str = ""

    def __str__(self):
        icon = "✓" if self.result == PeerVisibilityResult.PASS else "✗"
        expected_str = "VISIBLE" if self.probe.expected else "ABSENT"
        observed_str = "VISIBLE" if self.observed_visible else "ABSENT"
        return (
            f"{icon} {self.result.value}  | "
            f"expected={expected_str} observed={observed_str} | "
            f"{self.probe.description}"
            + (f" | ERROR: {self.error}" if self.error else "")
        )


# ── Real Database ──────────────────────────────────────────────────────────────

class RealDatabase(DatabaseInterface):
    """
    Reads from the real Postgres schema:
      users → headscale_identities → lab_deployments → subnet_pool
    """

    def __init__(self, conn_str: str):
        # Strip asyncpg driver prefix if present — psycopg2 doesn't need it
        conn_str = conn_str.replace("postgresql+asyncpg://", "postgresql://")
        self.conn = psycopg2.connect(conn_str)
        self.conn.autocommit = True
        self._users: Optional[list[User]] = None
        self._subnet_map: dict[str, SubnetAllocation] = {}
        self._router_ips: dict[str, str] = {}   # headscale_username → public IP

    def _load(self):
        if self._users is not None:
            return

        cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Join users → headscale_identities → lab_deployments → subnet_pool.
        # Only pull users who have a running lab-verifier deployment.
        cur.execute("""
            SELECT
                u.id                        AS user_id,
                u.email,
                COALESCE(u.name, u.email)   AS name,
                COALESCE(u.role, 'student') AS role,
                hi.headscale_username,
                sp.subnet_cidr,
                ld.terraform_outputs,
                ld.instance_public_ip
            FROM users u
            JOIN headscale_identities hi ON hi.user_id = u.id
            JOIN lab_deployments ld      ON ld.user_id = u.id
                                        AND ld.status   = 'running'
                                        AND ld.lab_type = 'lab-verifier'
            JOIN subnet_pool sp          ON sp.deployment_id = ld.id
                                        AND sp.status = 'in_use'
            WHERE u.is_active = true
            ORDER BY u.created_at
        """)

        rows = cur.fetchall()
        if not rows:
            print(
                "WARNING: No active lab-verifier deployments found in DB.",
                file=sys.stderr,
            )
            self._users = []
            return

        self._users = []

        for row in rows:
            role_str = (row["role"] or "student").lower()
            try:
                role = UserRole(role_str)
            except ValueError:
                role = UserRole.STUDENT

            user = User(
                id=str(row["user_id"]),
                email=row["email"],
                name=row["name"],
                role=role,
                is_active=True,
                headscale_username=row["headscale_username"],
            )
            self._users.append(user)
            self._subnet_map[user.id] = SubnetAllocation(
                user_id=user.id,
                subnet_cidr=row["subnet_cidr"],
            )

            # Router public IP: prefer terraform_outputs, fall back to column
            public_ip = self._extract_public_ip(row)
            if not public_ip:
                public_ip = row.get("instance_public_ip")
            if public_ip:
                self._router_ips[user.headscale_username] = public_ip

        print(
            f"Loaded {len(self._users)} user(s) with running lab-verifier deployments:",
            file=sys.stderr,
        )
        for u in self._users:
            subnet = self._subnet_map[u.id].subnet_cidr
            ip = self._router_ips.get(u.headscale_username, "NO IP")
            print(f"  {u.headscale_username} → {subnet} (router: {ip})", file=sys.stderr)

    def _extract_public_ip(self, row) -> Optional[str]:
        try:
            outputs = row["terraform_outputs"]
            if isinstance(outputs, str):
                outputs = json.loads(outputs)
            return (
                outputs["lab_summary"]["value"]["instances"]["subnet_router"]["public_ip"]
            )
        except (KeyError, TypeError, json.JSONDecodeError):
            return None

    def get_active_users(self) -> list[User]:
        self._load()
        return self._users

    def get_subnet_for_user(self, user_id: str) -> Optional[SubnetAllocation]:
        self._load()
        return self._subnet_map.get(user_id)

    def get_running_labs_for_user(self, user_id: str):
        return []

    def get_router_ip(self, headscale_username: str) -> Optional[str]:
        self._load()
        return self._router_ips.get(headscale_username)


# ── HuJSON Parser ──────────────────────────────────────────────────────────────

def parse_hujson(path: str) -> HeadscalePolicy:
    """
    Minimal huJSON parser — strips single-line (//) and block (/* */) comments,
    then parses as standard JSON.
    """
    with open(path) as f:
        raw = f.read()

    raw = re.sub(r'/\*.*?\*/', '', raw, flags=re.DOTALL)   # block comments
    raw = re.sub(r'//[^\n]*', '', raw)                      # line comments
    raw = re.sub(r',\s*([}\]])', r'\1', raw)                # trailing commas

    data = json.loads(raw)

    acls = [
        ACLRule(
            action=rule.get("action", "accept"),
            src=rule.get("src", []),
            dst=rule.get("dst", []),
            proto=rule.get("proto"),
        )
        for rule in data.get("acls", [])
    ]

    return HeadscalePolicy(
        tag_owners=data.get("tagOwners", {}),
        acls=acls,
        auto_approvers=data.get("autoApprovers", {}),
        hosts=data.get("hosts"),
    )


# ── Headscale API Client ───────────────────────────────────────────────────────

class HeadscaleClient:
    """
    Fetches Tailscale IP addresses for each router node from the Headscale API.
    Used to build headscale_username → tailscale_ip map for the probe generator.
    """

    def __init__(self, headscale_url: str, api_key: str):
        self.base_url = headscale_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def get_tailscale_ip_map(self) -> dict[str, str]:
        """
        Returns headscale_username → first 100.64.x.x Tailscale IP for all nodes.
        """
        resp = requests.get(
            f"{self.base_url}/api/v1/node",
            headers=self.headers,
            timeout=10,
        )
        resp.raise_for_status()
        nodes = resp.json().get("nodes", [])

        ip_map: dict[str, str] = {}
        for node in nodes:
            username = (node.get("user") or {}).get("name", "")
            if not username:
                continue
            for addr in node.get("ipAddresses", []):
                if addr.startswith("100.64."):
                    ip_map[username] = addr
                    break

        print(f"  Fetched Tailscale IPs for {len(ip_map)} node(s):", file=sys.stderr)
        for username, ip in ip_map.items():
            print(f"    {username} → {ip}", file=sys.stderr)

        return ip_map


# ── tailscale status Parser ────────────────────────────────────────────────────

def parse_tailscale_status(output: str) -> set[str]:
    """
    Parse the output of `tailscale status` and return the set of
    headscale_usernames of all visible peers (excluding self — first line).

    Line format observed on live routers:
      <tailscale_ip>  <hostname>  <headscale_username>@  <os>  <status...>

    Comments (lines starting with #) are ignored.
    The first non-comment line is the node itself — skipped so that
    positive probe self-checks don't need to call this at all.

    Returns a set of usernames WITHOUT the trailing @, matching the DB format.
    e.g. {"user-6360f798-2fdb-4c8f-a671-12cb35fcc3dd"}
    """
    peers: set[str] = set()
    non_comment_lines = [
        line for line in output.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    # Skip the first line — it's always the node itself
    for line in non_comment_lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        # Third field is headscale_username@ (with trailing @)
        username_field = parts[2]
        username = username_field.rstrip("@")
        if username:
            peers.add(username)

    return peers


# ── SSH Peer Visibility Executor ───────────────────────────────────────────────

class TailscaleStatusExecutor:
    """
    Executes probes by SSHing into each tenant's subnet router and running
    `tailscale status` to check peer visibility.

    Probe semantics:
      - Positive probe (expected=True):  src router must see itself — always
                                          PASS, resolved without SSH.
      - Negative probe (expected=False): src router must NOT see dst peer.
                                          PASS = peer absent, FAIL = peer present.

    One `tailscale status` call per source router covers all probes from that
    router — we batch them to avoid redundant SSH connections.
    """

    SSH_OPTS = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
    ]
    SSH_USER = "ubuntu"

    def __init__(self, db: RealDatabase, ssh_key_path: str):
        self.db = db
        self.ssh_key_path = ssh_key_path
        # Cache: headscale_username → set of visible peer usernames
        self._status_cache: dict[str, set[str]] = {}
        self._status_errors: dict[str, str] = {}

    def _fetch_tailscale_status(self, src_username: str) -> tuple[set[str] | None, str]:
        """
        SSH into the router for src_username and run `tailscale status`.
        Returns (visible_peer_usernames, error_string).

        Returns (None, error) on SSH failure — callers must treat None as
        indeterminate (ERROR), not as an empty peer set (which would be a
        spurious PASS for negative probes).

        Result is cached — subsequent calls for the same src_username reuse it.
        """
        if src_username in self._status_cache:
            return self._status_cache[src_username], self._status_errors.get(src_username, "")

        router_ip = self.db.get_router_ip(src_username)
        if not router_ip:
            err = f"No router IP found for {src_username}"
            self._status_cache[src_username] = None
            self._status_errors[src_username] = err
            return None, err

        cmd = [
            "ssh",
            *self.SSH_OPTS,
            "-i", self.ssh_key_path,
            f"{self.SSH_USER}@{router_ip}",
            "tailscale status",
        ]

        print(
            f"  SSH [{src_username}@{router_ip}] tailscale status ...",
            file=sys.stderr,
            end=" ",
        )

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=20
            )
            if result.returncode != 0 and not result.stdout.strip():
                err = f"SSH failed (rc={result.returncode}): {result.stderr.strip()}"
                print(f"ERROR: {err}", file=sys.stderr)
                self._status_cache[src_username] = None
                self._status_errors[src_username] = err
                return None, err

            peers = parse_tailscale_status(result.stdout)
            print(f"ok — {len(peers)} peer(s) visible", file=sys.stderr)
            self._status_cache[src_username] = peers
            self._status_errors[src_username] = ""
            return peers, ""

        except subprocess.TimeoutExpired:
            err = f"SSH timeout connecting to {router_ip}"
            print(f"TIMEOUT", file=sys.stderr)
            self._status_cache[src_username] = None
            self._status_errors[src_username] = err
            return None, err
        except Exception as e:
            err = str(e)
            print(f"ERROR: {err}", file=sys.stderr)
            self._status_cache[src_username] = None
            self._status_errors[src_username] = err
            return None, err

    def run(self, probes: list[Probe]) -> list[PeerVisibilityOutcome]:
        """
        Evaluate all probes. Batches SSH calls per source router.

        Positive probes (expected=True, src==dst user) are resolved locally —
        a router always sees itself, so no SSH call is needed.

        SSH failures produce ERROR outcomes, not FAIL — they indicate an
        infrastructure problem and must never be mistaken for ACL violations
        or used to trigger Phase 2 escalation.
        """
        outcomes: list[PeerVisibilityOutcome] = []

        for probe in probes:
            # ── Positive probe: router always sees itself ──────────────────────
            if probe.expected and probe.dst_user == probe.src_user:
                outcomes.append(PeerVisibilityOutcome(
                    probe=probe,
                    observed_visible=True,
                    result=PeerVisibilityResult.PASS,
                ))
                continue

            # ── Negative probe: check peer visibility via tailscale status ─────
            peers, error = self._fetch_tailscale_status(probe.src_user)

            if peers is None:
                # SSH failure — indeterminate, not an ACL violation
                outcomes.append(PeerVisibilityOutcome(
                    probe=probe,
                    observed_visible=False,
                    result=PeerVisibilityResult.ERROR,
                    error=error,
                ))
                continue

            target_username = probe.dst_user
            observed_visible = target_username in peers
            result = (
                PeerVisibilityResult.PASS
                if observed_visible == probe.expected
                else PeerVisibilityResult.FAIL
            )

            outcomes.append(PeerVisibilityOutcome(
                probe=probe,
                observed_visible=observed_visible,
                result=result,
            ))

        return outcomes


# ── Violation Reporter (peer-visibility aware) ─────────────────────────────────

class PeerVisibilityReporter:
    """
    Reports probe outcomes in terms of peer visibility.
    ERROR outcomes (SSH failures) are reported separately and never
    counted as violations or used to trigger Phase 2.
    """

    def report(self, outcomes: list[PeerVisibilityOutcome], label: str = "") -> None:
        if label:
            print("=" * 65)
            print(label)
            print("=" * 65)

        passed  = [o for o in outcomes if o.result == PeerVisibilityResult.PASS]
        failed  = [o for o in outcomes if o.result == PeerVisibilityResult.FAIL]
        errors  = [o for o in outcomes if o.result == PeerVisibilityResult.ERROR]

        isolation_leaks = [o for o in failed if not o.probe.expected and o.observed_visible]
        reach_failures  = [o for o in failed if o.probe.expected and not o.observed_visible]

        print(
            f"Total probes: {len(outcomes)}  |  "
            f"Passed: {len(passed)}  |  "
            f"Failed: {len(failed)}  |  "
            f"Errors (SSH): {len(errors)}"
        )
        print()

        if not failed and not errors:
            print("✓ All probes passed.")
            return

        if isolation_leaks:
            print(f"🚨 CRITICAL — Isolation leaks ({len(isolation_leaks)}):")
            print("   Peer is VISIBLE but should be ABSENT — cross-tenant ACL violation.\n")
            for o in isolation_leaks:
                print(f"   {o}")
            print()

        if reach_failures:
            print(f"⚠️  Reachability failures ({len(reach_failures)}):")
            print("   Peer is ABSENT but should be VISIBLE — user can't see own router.\n")
            for o in reach_failures:
                print(f"   {o}")
            print()

        if errors:
            print(f"⚙️  SSH errors — indeterminate ({len(errors)}):")
            print("   Could not reach router. Not counted as ACL violations.\n")
            for o in errors:
                print(f"   {o}")
            print()


# ── Helpers ────────────────────────────────────────────────────────────────────

def build_user_subnet_map(db: RealDatabase) -> dict[str, str]:
    """Build headscale_username → subnet_cidr map from DB."""
    result = {}
    for user in db.get_active_users():
        subnet = db.get_subnet_for_user(user.id)
        if subnet:
            result[user.headscale_username] = subnet.subnet_cidr
    return result


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberRange ACL Real Executor")
    parser.add_argument("--conn-str", required=True, help="Postgres connection string")
    parser.add_argument("--ssh-key", required=True, help="Path to SSH private key for subnet routers")
    parser.add_argument("--acl-file", required=True, help="Path to Headscale ACL policy .hujson file")
    parser.add_argument("--headscale-url", required=True, help="Headscale server URL")
    parser.add_argument("--headscale-api-key", required=True, help="Headscale API key")
    parser.add_argument(
        "--phase2-all", action="store_true",
        help="Run Phase 2 for all users regardless of Phase 1 results (useful for small N)",
    )
    args = parser.parse_args()

    print("=" * 65, file=sys.stderr)
    print("CyberRange ACL Real Executor (peer-visibility mode)", file=sys.stderr)
    print("=" * 65, file=sys.stderr)

    # ── Load DB ────────────────────────────────────────────────────────────────
    print("\nConnecting to DB...", file=sys.stderr)
    db = RealDatabase(args.conn_str)

    # ── Parse ACL ──────────────────────────────────────────────────────────────
    print("Parsing ACL policy...", file=sys.stderr)
    policy = parse_hujson(args.acl_file)
    print(f"  Loaded {len(policy.acls)} ACL rules", file=sys.stderr)

    # ── Build user/subnet map from DB (ground truth) ───────────────────────────
    user_subnet_map = build_user_subnet_map(db)
    if not user_subnet_map:
        print("ERROR: No users with running deployments found. Exiting.", file=sys.stderr)
        sys.exit(1)
    print(f"\nUsers to probe: {list(user_subnet_map.keys())}", file=sys.stderr)

    # ── Stage 0: Static policy check (structural, no SSH) ─────────────────────
    # Runs before any network probes. Catches WRONG_SUBNET, MISSING_RULE,
    # OVERLY_BROAD_RULE, PRIVILEGE_ESCALATION, DUPLICATE_RULES, ORPHAN_RULE
    # purely by diffing the ACL against DB ground truth.
    # WRONG_SUBNET in particular is invisible to the dynamic executor:
    # a user pointing to a non-existent /24 produces zero peers in
    # tailscale status (Phase 1 passes), but their own subnet is unreachable.
    # The static checker catches it here and escalates to Phase 2.
    print("\n" + "=" * 65, file=sys.stderr)
    print("STAGE 0: Static policy check (structural, no SSH)", file=sys.stderr)
    print("=" * 65, file=sys.stderr)
    static_checker = StaticPolicyChecker(db)
    static_result = static_checker.check(policy)
    static_result.report()
    static_flagged = static_result.flagged_users  # usernames to force into Phase 2

    # ── Fetch Tailscale IPs (for probe generation) ─────────────────────────────
    print("\nFetching Tailscale IPs from Headscale API...", file=sys.stderr)
    headscale = HeadscaleClient(args.headscale_url, args.headscale_api_key)
    tailscale_ip_map = headscale.get_tailscale_ip_map()

    # ── Set up probe generator and executors ───────────────────────────────────
    probe_gen = TwoPhaseProbeGenerator(policy, user_subnet_map, tailscale_ip_map)
    ssh_executor = TailscaleStatusExecutor(db, args.ssh_key)
    oracle = PolicyAwareExecutor(policy)
    reporter = PeerVisibilityReporter()

    all_real_outcomes: list[PeerVisibilityOutcome] = []
    all_probes_run: list[Probe] = []

    # ── Stage 1: Positive probes ───────────────────────────────────────────────
    print("\n" + "=" * 65, file=sys.stderr)
    print("STAGE 1: Positive probes (self-visibility, no SSH needed)", file=sys.stderr)
    print("=" * 65, file=sys.stderr)
    positive_probes = probe_gen.generate_positive_probes()
    positive_outcomes = ssh_executor.run(positive_probes)
    all_real_outcomes.extend(positive_outcomes)
    all_probes_run.extend(positive_probes)
    reporter.report(positive_outcomes, label="POSITIVE PROBE RESULTS")

    # ── Stage 2: Phase 1 sweep ─────────────────────────────────────────────────
    print("\n" + "=" * 65, file=sys.stderr)
    print("STAGE 2: Phase 1 canary sweep (O(N) isolation check)", file=sys.stderr)
    print("=" * 65, file=sys.stderr)
    phase1_probes = probe_gen.generate_phase1_probes()
    phase1_outcomes = ssh_executor.run(phase1_probes)
    all_real_outcomes.extend(phase1_outcomes)
    all_probes_run.extend(phase1_probes)
    reporter.report(phase1_outcomes, label="PHASE 1 SWEEP RESULTS")

    # Users who failed Phase 1 with a real ACL violation (not an SSH error)
    users_with_leaks = [
        o.probe.src_user for o in phase1_outcomes
        if o.result == PeerVisibilityResult.FAIL
    ]
    users_with_errors = [
        o.probe.src_user for o in phase1_outcomes
        if o.result == PeerVisibilityResult.ERROR
    ]

    # Merge in static checker flagged users — they need Phase 2 even if Phase 1
    # passed (e.g. WRONG_SUBNET: user points to a non-existent subnet so no peers
    # are visible, but their own subnet is also unreachable — Phase 1 can't see this).
    # Deduplicate while preserving order (Phase 1 failures first).
    seen_leak_users = set(users_with_leaks)
    for username in static_flagged:
        if username not in seen_leak_users and username not in users_with_errors:
            users_with_leaks.append(username)
            seen_leak_users.add(username)

    if static_flagged:
        newly_escalated = [u for u in static_flagged if u in seen_leak_users]
        print(
            f"\n→ Static checker escalated to Phase 2: {static_flagged}",
            file=sys.stderr,
        )

    if args.phase2_all:
        users_with_leaks = list(user_subnet_map.keys())
        print(
            f"\n--phase2-all: running Phase 2 for all {len(users_with_leaks)} users",
            file=sys.stderr,
        )
    elif users_with_leaks:
        print(f"\n→ Leak detected for: {users_with_leaks}", file=sys.stderr)
        print(f"→ Triggering Phase 2 for {len(users_with_leaks)} user(s)...", file=sys.stderr)
    else:
        print("\n→ No leaks detected. Phase 2 not needed.", file=sys.stderr)

    if users_with_errors:
        print(
            f"→ SSH errors for {users_with_errors} — skipping Phase 2 for these "
            f"(infrastructure problem, not an ACL violation).",
            file=sys.stderr,
        )

    # ── Stage 3: Phase 2 localisation ─────────────────────────────────────────
    phase2_outcomes: list[PeerVisibilityOutcome] = []
    if users_with_leaks:
        print("\n" + "=" * 65, file=sys.stderr)
        print("STAGE 3: Phase 2 localisation (targeted boundary testing)", file=sys.stderr)
        print("=" * 65, file=sys.stderr)
        phase2_probes = probe_gen.generate_phase2_probes(users_with_leaks)
        phase2_outcomes = ssh_executor.run(phase2_probes)
        all_real_outcomes.extend(phase2_outcomes)
        all_probes_run.extend(phase2_probes)
        reporter.report(phase2_outcomes, label="PHASE 2 LOCALISATION RESULTS")

    # ── Oracle comparison ──────────────────────────────────────────────────────
    # Only compare negative probes (phase > 0), excluding ERROR outcomes.
    # Positive probes use self-visibility semantics that don't map to the oracle.
    # .value string comparison avoids cross-enum-class inequality.
    print("\n" + "=" * 65, file=sys.stderr)
    print("ORACLE COMPARISON (policy executor vs tailscale status)", file=sys.stderr)
    print("=" * 65, file=sys.stderr)

    negative_real = [
        (i, o) for i, o in enumerate(all_real_outcomes)
        if o.probe.phase > 0 and o.result != PeerVisibilityResult.ERROR
    ]
    negative_probes = [all_probes_run[i] for i, _ in negative_real]
    oracle_outcomes = oracle.run(negative_probes)

    mismatches = []
    for (_, real), ora in zip(negative_real, oracle_outcomes):
        if real.result.value != ora.result.value:
            mismatches.append((real, ora))

    if not mismatches:
        print("✓ Real executor and oracle agree on all negative probes.", file=sys.stderr)
    else:
        print(
            f"⚠️  {len(mismatches)} discrepancies between real and oracle:",
            file=sys.stderr,
        )
        for real, ora in mismatches:
            print(
                f"  {real.probe.src_user} → {real.probe.dst_user} | "
                f"real={real.result.value} oracle={ora.result.value} | "
                f"{real.probe.description}",
                file=sys.stderr,
            )

    # ── Final summary ──────────────────────────────────────────────────────────
    total = len(all_real_outcomes)
    all_failed  = [o for o in all_real_outcomes if o.result == PeerVisibilityResult.FAIL]
    all_errored = [o for o in all_real_outcomes if o.result == PeerVisibilityResult.ERROR]

    print("\n" + "=" * 65)
    print("FINAL SUMMARY")
    print("=" * 65)
    print(f"Static violations:     {len(static_result.violations)}")
    print(f"Total probes run:      {total}")
    print(f"  Positive probes:     {len(positive_outcomes)}")
    print(f"  Phase 1 probes:      {len(phase1_outcomes)}")
    print(f"  Phase 2 probes:      {len(phase2_outcomes)}")
    print(f"Users with leaks:      {len(users_with_leaks)}")
    print(f"Dynamic violations:    {len(all_failed)}")
    print(f"SSH errors (skipped):  {len(all_errored)}")
    print(f"Oracle mismatches:     {len(mismatches)}")

    any_violations = bool(static_result.violations or all_failed)
    if not any_violations and not all_errored:
        print("\n✓ ACL correctly enforces peer isolation. No violations found.")
    elif not any_violations and all_errored:
        print(f"\n⚠️  No ACL violations, but {len(all_errored)} router(s) were unreachable via SSH.")
        print("   Re-run when all routers are up to get a complete picture.")
    else:
        if static_result.violations:
            print(f"\n🚨 {len(static_result.violations)} structural violation(s) found by static checker.")
        if all_failed:
            print(f"🚨 {len(all_failed)} dynamic ACL violation(s) detected.")
        print("   Review ACL rules for the affected users.")

    sys.exit(1 if any_violations else 0)


if __name__ == "__main__":
    main()