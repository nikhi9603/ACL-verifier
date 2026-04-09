"""
Policy-Aware Executor.

Evaluates probes against the actual ACL rules rather than using pattern-based
simulation. For each probe (src_user, dst_ip, port, proto), it:
  1. Finds all ACL rules whose src matches the probe's source user
  2. Checks whether dst_ip falls within the rule's destination CIDR
  3. Checks whether the port is permitted by the rule
  4. Returns ALLOW if any rule matches, DENY otherwise (deny-by-default)

This faithfully models Headscale's forwarding semantics since Headscale's
enforcement is fully described by the ACL policy file.
"""

import ipaddress
from dataclasses import dataclass
from enum import Enum
from acl_generator.generator import HeadscalePolicy, ACLRule
from probe_generator.generator import Probe


class ProbeResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass
class ProbeOutcome:
    probe: Probe
    observed: bool
    result: ProbeResult
    matched_rule: int = -1  # Index of ACL rule that matched, -1 if denied
    error: str = ""

    def __str__(self):
        icon = "✓" if self.result == ProbeResult.PASS else "✗"
        expected_str = "ALLOW" if self.probe.expected else "DENY"
        observed_str = "ALLOW" if self.observed else "DENY"
        rule_str = f" [matched rule {self.matched_rule}]" if self.matched_rule >= 0 else " [no rule matched]"
        return (f"{icon} {self.result.value}  | expected={expected_str} "
                f"observed={observed_str}{rule_str} | {self.probe.description}")


class PolicyAwareExecutor:
    """
    Evaluates probes against the ACL policy directly.
    Models Headscale's deny-by-default, first-match semantics.
    """

    def __init__(self, policy: HeadscalePolicy):
        self.policy = policy

    def _src_matches(self, rule: ACLRule, src_user: str) -> bool:
        """Check if a rule's src list covers the given user."""
        for src_entry in rule.src:
            # Wildcard matches everyone
            if src_entry == "*":
                return True
            # User entry format: "username@"
            if src_entry.endswith("@"):
                if src_entry[:-1] == src_user:
                    return True
        return False

    def _dst_matches(self, rule: ACLRule, dst_ip: str, dst_port: int) -> bool:
        """Check if a rule's dst list covers the given (dst_ip, dst_port) pair."""
        for dst_entry in rule.dst:
            # Format: "subnet_or_ip:port_spec"
            if ":" in dst_entry:
                addr_part, port_part = dst_entry.rsplit(":", 1)
            else:
                addr_part = dst_entry
                port_part = "*"

            # Check IP/subnet match
            try:
                if "/" in addr_part:
                    # CIDR match
                    network = ipaddress.ip_network(addr_part, strict=False)
                    ip = ipaddress.ip_address(dst_ip)
                    if ip not in network:
                        continue
                else:
                    # Exact IP match
                    if addr_part != dst_ip and addr_part != "*":
                        continue
            except ValueError:
                continue

            # Check port match
            if port_part == "*":
                return True
            # ICMP probe (port 0) — treat as wildcard match
            if dst_port == 0:
                return True
            # Comma-separated ports: "22,80,443"
            allowed_ports = [p.strip() for p in port_part.split(",")]
            if str(dst_port) in allowed_ports:
                return True

        return False

    def evaluate_probe(self, probe: Probe) -> ProbeOutcome:
        """
        Evaluate a single probe against the ACL.
        Returns ALLOW if any rule matches, DENY otherwise.
        """
        for i, rule in enumerate(self.policy.acls):
            if rule.action != "accept":
                continue
            if self._src_matches(rule, probe.src_user) and \
               self._dst_matches(rule, probe.dst_ip, probe.dst_port):
                # Rule matched — probe is allowed
                observed = True
                result = ProbeResult.PASS if observed == probe.expected else ProbeResult.FAIL
                return ProbeOutcome(probe=probe, observed=observed,
                                    result=result, matched_rule=i)

        # No rule matched — deny by default
        observed = False
        result = ProbeResult.PASS if observed == probe.expected else ProbeResult.FAIL
        return ProbeOutcome(probe=probe, observed=observed, result=result, matched_rule=-1)

    def run(self, probes: list) -> list:
        """Evaluate all probes and return outcomes."""
        return [self.evaluate_probe(probe) for probe in probes]


class ViolationReporter:
    """Analyzes probe outcomes and produces a violation report."""

    def report(self, outcomes: list) -> None:
        passed = [o for o in outcomes if o.result == ProbeResult.PASS]
        failed = [o for o in outcomes if o.result == ProbeResult.FAIL]
        false_allows = [o for o in failed if not o.probe.expected and o.observed]
        false_denies = [o for o in failed if o.probe.expected and not o.observed]

        print("=" * 65)
        print("PROBE EVALUATION REPORT")
        print("=" * 65)
        print(f"Total probes evaluated: {len(outcomes)}")
        print(f"Passed:                 {len(passed)}")
        print(f"Failed:                 {len(failed)}")
        print()

        if not failed:
            print("✓ All probes passed. ACL correctly enforces isolation policy.")
            return

        print(f"VIOLATIONS DETECTED ({len(failed)} total)")
        print("-" * 65)

        if false_allows:
            print(f"\n🚨 CRITICAL — Isolation violations ({len(false_allows)}):")
            print("   Probes that should be DENIED were ALLOWED by the ACL.\n")
            for o in false_allows:
                print(f"   {o}")

        if false_denies:
            print(f"\n⚠️  Reachability failures ({len(false_denies)}):")
            print("   Probes that should be ALLOWED were DENIED by the ACL.\n")
            for o in false_denies:
                print(f"   {o}")

        print()
        print("=" * 65)
        print("Recommendation: Review ACL rules for the affected users.")


if __name__ == "__main__":
    from synthetic_data.generator import generate_synthetic_db
    from acl_generator.generator import ACLGenerator, ACLRule
    from probe_generator.generator import ProbeGenerator

    db = generate_synthetic_db(num_students=5, num_instructors=1)
    policy = ACLGenerator(db).generate()

    user_subnet_map = {}
    for user in db.get_active_users():
        subnet = db.get_subnet_for_user(user.id)
        if subnet:
            user_subnet_map[user.headscale_username] = subnet.subnet_cidr

    probes = ProbeGenerator(policy, user_subnet_map).generate()
    reporter = ViolationReporter()

    # --- TEST 1: Clean policy ---
    print("TEST 1: Clean policy — no faults")
    print("=" * 65)
    outcomes = PolicyAwareExecutor(policy).run(probes)
    reporter.report(outcomes)

    # --- TEST 2: Missing rule (student3's rule removed) ---
    print("\nTEST 2: Missing rule — student3's ACL entry removed")
    print("=" * 65)
    import copy
    faulty_policy = copy.deepcopy(policy)
    faulty_policy.acls = [r for r in faulty_policy.acls
                           if not (len(r.src) == 1 and r.src[0] == "student3@")]
    outcomes2 = PolicyAwareExecutor(faulty_policy).run(probes)
    reporter.report(outcomes2)

    # --- TEST 3: Overly broad rule (student2 gets full management subnet) ---
    print("\nTEST 3: Overly broad rule — student2 can reach entire 10.20.0.0/16")
    print("=" * 65)
    faulty_policy2 = copy.deepcopy(policy)
    for rule in faulty_policy2.acls:
        if len(rule.src) == 1 and rule.src[0] == "student2@":
            rule.dst = ["10.20.0.0/16:*"]
    outcomes3 = PolicyAwareExecutor(faulty_policy2).run(probes)
    reporter.report(outcomes3)

    # --- TEST 4: Wrong subnet (student1 points to student2's subnet) ---
    print("\nTEST 4: Wrong subnet — student1's rule points to student2's subnet")
    print("=" * 65)
    faulty_policy3 = copy.deepcopy(policy)
    for rule in faulty_policy3.acls:
        if len(rule.src) == 1 and rule.src[0] == "student1@":
            rule.dst = ["10.20.3.0/24:*"]  # student2's subnet
    outcomes4 = PolicyAwareExecutor(faulty_policy3).run(probes)
    reporter.report(outcomes4)