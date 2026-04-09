"""
Mock Probe Executor.

Simulates running network probes without touching a real network.
The mock can be configured to:
  - Run correctly (all probes match expected results) — baseline test
  - Inject specific failures (simulate misconfigured ACLs) — fault injection test

When you're ready to run against the real network, swap this out for
the real executor that uses subprocess + ping/nmap/scapy.
"""

import random
from dataclasses import dataclass
from enum import Enum
from probe_generator.generator import Probe


class ProbeResult(Enum):
    PASS = "PASS"   # Observed behavior matched expected
    FAIL = "FAIL"   # Observed behavior did not match expected


@dataclass
class ProbeOutcome:
    probe: Probe
    observed: bool          # True = reachable, False = not reachable
    result: ProbeResult
    latency_ms: float = 0.0
    error: str = ""

    def __str__(self):
        icon = "✓" if self.result == ProbeResult.PASS else "✗"
        expected_str = "ALLOW" if self.probe.expected else "DENY"
        observed_str = "ALLOW" if self.observed else "DENY"

        if self.result == ProbeResult.PASS:
            return (f"{icon} PASS  | expected={expected_str} observed={observed_str} "
                    f"| {self.probe.description}")
        else:
            return (f"{icon} FAIL  | expected={expected_str} observed={observed_str} "
                    f"| {self.probe.description}")


class MockExecutor:
    """
    Simulates probe execution.

    fault_injections: list of probe descriptions (substrings) that should
    be made to FAIL. This lets you simulate specific ACL misconfigurations.

    Example fault injections:
      - "student1 -> 10.20.2.0/24 (should allow)"  # student1 can't reach own subnet
      - "isolation: student2 -> 10.20.1.0"          # student2 can reach student1's subnet
    """

    def __init__(self, fault_injections: list[str] = None, noise: bool = False):
        """
        Args:
            fault_injections: List of description substrings to inject failures into
            noise: If True, randomly flip ~5% of results to simulate flaky network
        """
        self.fault_injections = fault_injections or []
        self.noise = noise

    def _should_inject_fault(self, probe: Probe) -> bool:
        for pattern in self.fault_injections:
            if pattern in probe.description:
                return True
        return False

    def _simulate_probe(self, probe: Probe) -> tuple[bool, float]:
        """
        Simulate running a probe. Returns (reachable, latency_ms).
        Without fault injection, the network behaves exactly as the ACL says.
        """
        # Base result: network correctly enforces the ACL
        reachable = probe.expected

        # Inject fault if configured
        if self._should_inject_fault(probe):
            reachable = not reachable  # Flip the result

        # Add noise if configured (5% random flip)
        if self.noise and random.random() < 0.05:
            reachable = not reachable

        # Simulate latency (allowed traffic has measurable latency, denied is instant)
        latency_ms = round(random.uniform(1.0, 15.0), 2) if reachable else 0.0

        return reachable, latency_ms

    def run(self, probes: list[Probe]) -> list[ProbeOutcome]:
        """Run all probes and return outcomes."""
        outcomes = []
        for probe in probes:
            observed, latency_ms = self._simulate_probe(probe)
            result = ProbeResult.PASS if observed == probe.expected else ProbeResult.FAIL
            outcomes.append(ProbeOutcome(
                probe=probe,
                observed=observed,
                result=result,
                latency_ms=latency_ms
            ))
        return outcomes


class ViolationReporter:
    """Analyzes probe outcomes and produces a violation report."""

    def report(self, outcomes: list[ProbeOutcome]) -> None:
        passed = [o for o in outcomes if o.result == ProbeResult.PASS]
        failed = [o for o in outcomes if o.result == ProbeResult.FAIL]

        # Categorize failures
        false_allows = [o for o in failed if o.probe.expected is False and o.observed is True]
        false_denies = [o for o in failed if o.probe.expected is True and o.observed is False]

        print("=" * 60)
        print("PROBE EXECUTION REPORT")
        print("=" * 60)
        print(f"Total probes run:     {len(outcomes)}")
        print(f"Passed:               {len(passed)}")
        print(f"Failed:               {len(failed)}")
        print()

        if not failed:
            print("✓ All probes passed. ACL isolation is correctly enforced.")
            return

        print(f"VIOLATIONS DETECTED ({len(failed)} total)")
        print("-" * 60)

        if false_allows:
            print(f"\n🚨 CRITICAL — Isolation violations ({len(false_allows)}):")
            print("   These probes should have been DENIED but were ALLOWED.")
            print("   This means a user can reach another tenant's subnet.\n")
            for o in false_allows:
                print(f"   {o}")

        if false_denies:
            print(f"\n⚠️  Reachability failures ({len(false_denies)}):")
            print("   These probes should have been ALLOWED but were DENIED.")
            print("   This means a user cannot reach their own subnet.\n")
            for o in false_denies:
                print(f"   {o}")

        print()
        print("=" * 60)
        print("Recommendation: Review the ACL rules for the affected users.")


if __name__ == "__main__":
    from synthetic_data.generator import generate_synthetic_db
    from acl_generator.generator import ACLGenerator
    from probe_generator.generator import ProbeGenerator

    db = generate_synthetic_db(num_students=5, num_instructors=1)
    generator = ACLGenerator(db)
    policy = generator.generate()

    user_subnet_map = {}
    for user in db.get_active_users():
        subnet = db.get_subnet_for_user(user.id)
        if subnet:
            user_subnet_map[user.headscale_username] = subnet.subnet_cidr

    probe_gen = ProbeGenerator(policy, user_subnet_map)
    probes = probe_gen.generate()

    print("=" * 60)
    print("TEST 1: Clean ACL — no faults injected")
    print("=" * 60)
    executor = MockExecutor()
    outcomes = executor.run(probes)
    reporter = ViolationReporter()
    reporter.report(outcomes)

    print()
    print("=" * 60)
    print("TEST 2: Fault injection — student2 can reach student1's subnet")
    print("        (simulates a misconfigured ACL allowing cross-tenant access)")
    print("=" * 60)
    faulty_executor = MockExecutor(fault_injections=[
        "isolation: student2 -> 10.20.1.0"
    ])
    faulty_outcomes = faulty_executor.run(probes)
    reporter.report(faulty_outcomes)

    print()
    print("=" * 60)
    print("TEST 3: Fault injection — student4 can't reach their own subnet")
    print("        (simulates a missing ACL rule for a user)")
    print("=" * 60)
    missing_rule_executor = MockExecutor(fault_injections=[
        "rule 4: student4 -> 10.20.5.0/24 (should allow)"
    ])
    missing_outcomes = missing_rule_executor.run(probes)
    reporter.report(missing_outcomes)