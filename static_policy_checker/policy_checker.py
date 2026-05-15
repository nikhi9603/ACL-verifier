"""
Static Policy Checker.

Performs structural analysis of a Headscale ACL policy against the DB ground truth
WITHOUT running any probes. Catches violations that are structurally visible:

  MISSING_RULE         — user has a subnet in DB but no ACL rule
  WRONG_SUBNET         — user's ACL rule points to a subnet not assigned to them
  OVERLY_BROAD_RULE    — user's ACL rule covers more than their /24 (e.g. a /16)
  DUPLICATE_RULES      — user has more than one ACL rule
  PRIVILEGE_ESCALATION — non-admin user has a rule covering the management subnet
  ORPHAN_RULE          — ACL rule references a user not in the DB
  NARROW_RULE          — user's ACL rule covers less than their /24 (eg: /27)

Phase 2 escalation policy (StaticCheckResult.flagged_users):
  WRONG_SUBNET, OVERLY_BROAD_RULE, PRIVILEGE_ESCALATION → escalated to Phase 2
  MISSING_RULE, DUPLICATE_RULES                         → NOT escalated
    (missing rule = user can't reach anything, not an isolation leak;
     duplicate rule = doesn't grant extra access on its own)
  ORPHAN_RULE                                           → NOT escalated
    (references a non-existent user — no router to SSH into)
  NARROW_RULE                                           → NOT escalated
  (Narrow rules are checked after WRONG_SUBNET detection. Remaining cases only reduce to reachability within the tenant's own subnet and are not isolation leaks to escalate to Phase 2)
"""

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from models.policy import HeadscalePolicy, ACLRule
from models.db_interface import DatabaseInterface
from models.db_models import UserRole, User


class ViolationType(str, Enum):
    MISSING_RULE         = "MISSING_RULE"
    WRONG_SUBNET         = "WRONG_SUBNET"
    OVERLY_BROAD_RULE    = "OVERLY_BROAD_RULE"
    DUPLICATE_RULES      = "DUPLICATE_RULES"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    ORPHAN_RULE          = "ORPHAN_RULE"
    NARROW_RULE          = "NARROW_RULE"


@dataclass
class StaticViolation:
    violation_type: ViolationType
    username: str
    detail: str

    def __str__(self):
        return f"[{self.violation_type.value}] {self.username}: {self.detail}"


@dataclass
class StaticCheckResult:
    violations: list[StaticViolation] = field(default_factory=list)

    @property
    def flagged_users(self) -> list[str]:
        """
        Returns usernames to escalate to Phase 2 dynamic probing.

        Only violation types that can cause isolation failures are escalated:
          WRONG_SUBNET       — user may reach another tenant's subnet
          OVERLY_BROAD_RULE  — rule covers more than one tenant's /24
          PRIVILEGE_ESCALATION — rule covers management address space

        Excluded:
          MISSING_RULE    — user can't reach anything; not an isolation leak
          DUPLICATE_RULES — doesn't grant extra access on its own
          ORPHAN_RULE     — references a non-existent user; no router to probe
          NARROW_RULE     — checked after WRONG_SUBNET detection. Remaining cases only reduce to reachability within the tenant's own subnet; not an isolation leak
        """
        escalate_types = {
            ViolationType.WRONG_SUBNET,
            ViolationType.OVERLY_BROAD_RULE,
            ViolationType.PRIVILEGE_ESCALATION,
        }
        seen = set()
        users = []
        for v in self.violations:
            if v.violation_type in escalate_types and v.username not in seen:
                seen.add(v.username)
                users.append(v.username)
        return users

    @property
    def passed(self) -> bool:
        return len(self.violations) == 0

    def report(self) -> None:
        print("=" * 65)
        print("STATIC POLICY CHECK REPORT")
        print("=" * 65)

        if self.passed:
            print("✓ No structural violations found.")
            return

        by_type: dict[ViolationType, list[StaticViolation]] = {}
        for v in self.violations:
            by_type.setdefault(v.violation_type, []).append(v)

        print(f"Violations found: {len(self.violations)}")
        print()

        severity_order = [
            ViolationType.PRIVILEGE_ESCALATION,
            ViolationType.OVERLY_BROAD_RULE,
            ViolationType.WRONG_SUBNET,
            ViolationType.MISSING_RULE,
            ViolationType.NARROW_RULE,
            ViolationType.DUPLICATE_RULES,
            ViolationType.ORPHAN_RULE,
        ]

        for vtype in severity_order:
            if vtype not in by_type:
                continue
            is_critical = vtype in {
                ViolationType.PRIVILEGE_ESCALATION,
                ViolationType.OVERLY_BROAD_RULE,
                ViolationType.WRONG_SUBNET,
            }
            prefix = "🚨 CRITICAL" if is_critical else "⚠️  WARNING"
            print(f"{prefix} — {vtype.value} ({len(by_type[vtype])})")
            for v in by_type[vtype]:
                print(f"   {v.username}: {v.detail}")
            print()

        flagged = self.flagged_users
        if flagged:
            print(f"→ {len(flagged)} user(s) escalated to Phase 2: {flagged}")

        print("=" * 65)


class StaticPolicyChecker:
    """
    Checks a HeadscalePolicy structurally against the DB ground truth.
    No probes are run — this is purely a diff of what the DB says vs what the ACL says.
    """

    MANAGEMENT_SUBNET = "10.20.0.0/16"

    def __init__(self, db: DatabaseInterface):
        self.db = db

    def _extract_username_from_src(self, src_entry: str) -> Optional[str]:
        """Parse 'username@' → 'username'. Returns None for wildcards or tags."""
        if src_entry.endswith("@") and src_entry != "@":
            return src_entry[:-1]
        return None

    def _extract_cidr_from_dst(self, dst_entry: str) -> Optional[str]:
        """Parse 'cidr:port' → 'cidr'. Returns None if unparseable."""
        addr = dst_entry.rsplit(":", 1)[0] if ":" in dst_entry else dst_entry
        try:
            ipaddress.ip_network(addr, strict=False)
            return addr
        except ValueError:
            return None

    def _cidr_prefix_len(self, cidr: str) -> int:
        return ipaddress.IPv4Network(cidr, strict=False).prefixlen

    def check(self, policy: HeadscalePolicy) -> StaticCheckResult:
        result = StaticCheckResult()
        active_users = self.db.get_active_users()

        # Build lookup maps from DB
        db_user_map: dict[str, User] = {u.headscale_username: u for u in active_users}
        db_subnet_map: dict[str, str] = self.db.get_user_subnet_map()

        # Build a map of username → list of ACL rules that reference them
        acl_rules_by_user: dict[str, list[ACLRule]] = {}
        for rule in policy.acls:
            if rule.action != "accept":
                continue
            for src_entry in rule.src:
                username = self._extract_username_from_src(src_entry)
                if username:
                    acl_rules_by_user.setdefault(username, []).append(rule)

        # --- Check 1: MISSING_RULE — DB user has no ACL rule ---
        for username in db_subnet_map:
            user = db_user_map[username]
            if user.role == UserRole.ADMIN:
                continue  # Admins have a shared rule, not per-user rules
            if username not in acl_rules_by_user:
                result.violations.append(StaticViolation(
                    violation_type=ViolationType.MISSING_RULE,
                    username=username,
                    detail=f"User has subnet {db_subnet_map[username]} in DB but no ACL rule found"
                ))

        # --- Check 2: ORPHAN_RULE — ACL rule references a user not in DB ---
        for username in acl_rules_by_user:
            if username not in db_user_map:
                result.violations.append(StaticViolation(
                    violation_type=ViolationType.ORPHAN_RULE,
                    username=username,
                    detail=f"ACL has rule for '{username}' but this user is not in the DB"
                ))

        # --- Checks 3–6: Per-user rule analysis ---
        for username, rules in acl_rules_by_user.items():
            if username not in db_user_map:
                continue  # Already flagged as ORPHAN_RULE above

            user = db_user_map[username]
            expected_subnet = db_subnet_map.get(username)

            # Check 3: DUPLICATE_RULES
            if len(rules) > 1:
                result.violations.append(StaticViolation(
                    violation_type=ViolationType.DUPLICATE_RULES,
                    username=username,
                    detail=f"User has {len(rules)} ACL rules (expected 1)"
                ))

            for rule in rules:
                for dst_entry in rule.dst:
                    cidr = self._extract_cidr_from_dst(dst_entry)
                    if not cidr:
                        continue

                    # Check 4: PRIVILEGE_ESCALATION
                    # Tenant /24s (e.g. 10.20.2.0/24) legitimately sit inside the
                    # management /16 by CIDR containment — we can't use subnet_of().
                    # We use overlaps(): flag any rule broader than /24 that touches
                    # the management address space at all.
                    # Note: supernet_of() would be too narrow — it misses cases like
                    # 10.20.0.0/15 which overlaps but doesn't fully contain the /16.
                    if user.role != UserRole.ADMIN:
                        rule_net = ipaddress.IPv4Network(cidr, strict=False)
                        mgmt_net = ipaddress.IPv4Network(self.MANAGEMENT_SUBNET, strict=False)
                        if rule_net.prefixlen < 24 and rule_net.overlaps(mgmt_net):
                            result.violations.append(StaticViolation(
                                violation_type=ViolationType.PRIVILEGE_ESCALATION,
                                username=username,
                                detail=(f"Non-admin user has rule pointing to management "
                                        f"subnet area: {cidr}")
                            ))
                            continue

                    # Check 5: OVERLY_BROAD_RULE
                    if self._cidr_prefix_len(cidr) < 24:
                        result.violations.append(StaticViolation(
                            violation_type=ViolationType.OVERLY_BROAD_RULE,
                            username=username,
                            detail=(f"Rule destination {cidr} is broader than /24 — "
                                    f"may grant access to other tenants' subnets")
                        ))
                        continue

                    rule_net = ipaddress.IPv4Network(cidr, strict=False)
                    expected_net = ipaddress.IPv4Network(expected_subnet, strict=False)
                    # Check 6: WRONG_SUBNET
                    if expected_net and rule_net.network_address != expected_net.network_address:
                        result.violations.append(StaticViolation(
                            violation_type=ViolationType.WRONG_SUBNET,
                            username=username,
                            detail=(f"Rule points to {cidr} but DB assigns "
                                    f"{expected_subnet} to this user")
                        ))
                        continue
                    
                    # Check 7: NARROW_RULE
                    if self._cidr_prefix_len(cidr) > 24:
                        result.violations.append(StaticViolation(
                            violation_type=ViolationType.NARROW_RULE,
                            username=username,
                            detail=(f"Rule destination {cidr} is narrower than /24 — "
                                    f"may partial cover the tenant subnet")
                        ))

        return result


if __name__ == "__main__":
    from synthetic_data.generator import generate_synthetic_db
    from acl_generator.generator import ACLGenerator
    from models.policy import ACLRule
    import copy

    db = generate_synthetic_db(num_students=5, num_instructors=1)
    policy = ACLGenerator(db).generate()
    checker = StaticPolicyChecker(db)

    print("TEST 1: Clean policy — no violations expected")
    checker.check(policy).report()

    print()
    print("TEST 2: Missing rule — student3's rule removed")
    faulty = copy.deepcopy(policy)
    faulty.acls = [r for r in faulty.acls
                   if not (len(r.src) == 1 and r.src[0] == "student3@")]
    checker.check(faulty).report()

    print()
    print("TEST 3: Wrong subnet — student1 points to student2's subnet")
    faulty3 = copy.deepcopy(policy)
    for rule in faulty3.acls:
        if len(rule.src) == 1 and rule.src[0] == "student1@":
            rule.dst = ["10.20.3.0/24:*"]
    checker.check(faulty3).report()

    print()
    print("TEST 4: Overly broad rule — student2 gets a /23")
    faulty4 = copy.deepcopy(policy)
    for rule in faulty4.acls:
        if len(rule.src) == 1 and rule.src[0] == "student2@":
            rule.dst = ["10.20.3.0/23:*"]
    checker.check(faulty4).report()

    print()
    print("TEST 5: Privilege escalation — student4 points to management /16")
    faulty5 = copy.deepcopy(policy)
    for rule in faulty5.acls:
        if len(rule.src) == 1 and rule.src[0] == "student4@":
            rule.dst = ["10.20.0.0/16:*"]
    checker.check(faulty5).report()

    print()
    print("TEST 6: Orphan rule — rule for a user not in DB")
    faulty6 = copy.deepcopy(policy)
    faulty6.acls.append(ACLRule(
        action="accept",
        src=["ghost_user@"],
        dst=["10.20.99.0/24:*"]
    ))
    checker.check(faulty6).report()

    print()
    print("TEST 7: Narrow rule — student1 gets a /28")
    faulty7 = copy.deepcopy(policy)
    for rule in faulty7.acls:
        if len(rule.src) == 1 and rule.src[0] == "student1@":
            rule.dst = ["10.20.2.0/28:*"]
    checker.check(faulty7).report()