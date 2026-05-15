"""
Two-Phase Pipeline.

Orchestrates the full two-phase adaptive probing workflow:
  1. Static policy check   — structural diff of ACL vs DB, no network
  2. Positive probes       — verify each user can reach their own subnet
  3. Phase 1 sweep         — O(N) isolation check
  4. Phase 2 localisation  — only for users flagged by Phase 1 or static checker
  5. Report all violations with precise boundary localisation
"""

import copy
from probe_generator.two_phase_generator import TwoPhaseProbeGenerator
from probe_executor.policy_executor import PolicyAwareExecutor, ProbeResult, ViolationReporter
from models.db_interface import DatabaseInterface
from static_policy_checker.policy_checker import StaticPolicyChecker


class TwoPhasePipeline:

    def __init__(self, policy, db: DatabaseInterface):
        self.policy = policy
        self.db = db
        self.user_subnet_map = db.get_user_subnet_map()
        self.generator = TwoPhaseProbeGenerator(self.user_subnet_map)
        self.executor = PolicyAwareExecutor(policy)
        self.reporter = ViolationReporter()
        self.static_checker = StaticPolicyChecker(db)

    def run(self, verbose: bool = True) -> dict:
        """
        Execute the full two-phase pipeline.
        Returns a summary dict with probe counts and violations found.
        """
        results = {
            "static_result": None,
            "positive_outcomes": [],
            "phase1_outcomes": [],
            "phase2_outcomes": [],
            "users_with_leaks": [],
            "total_probes_run": 0,
        }

        # --- Stage 0: Static policy check ---
        # Catches structural violations (WRONG_SUBNET, OVERLY_BROAD_RULE,
        # PRIVILEGE_ESCALATION, MISSING_RULE, DUPLICATE_RULES, ORPHAN_RULE, NARROW_RULE)
        # without touching the network. Flagged users are escalated to Phase 2
        # even if Phase 1 passes — this is the only way to catch WRONG_SUBNET
        # (a user pointing to a non-existent subnet shows 0 peers in Phase 1,
        # which looks clean, but the static checker sees the mismatch).
        static_result = self.static_checker.check(self.policy)
        results["static_result"] = static_result
        static_flagged = set(static_result.flagged_users)

        if verbose:
            print("=" * 65)
            print("STAGE 0: STATIC POLICY CHECK")
            print("=" * 65)
            static_result.report()

        # --- Stage 1: Positive probes ---
        positive_probes = self.generator.generate_positive_probes()
        positive_outcomes = self.executor.run(positive_probes)
        results["positive_outcomes"] = positive_outcomes
        results["total_probes_run"] += len(positive_probes)
        positive_failure_users = {
            o.probe.src_user for o in positive_outcomes
            if o.result == ProbeResult.FAIL
        }

        if verbose:
            print()
            print("=" * 65)
            print("STAGE 1: POSITIVE PROBES (reachability verification)")
            print("=" * 65)
            self.reporter.report(positive_outcomes)

        # --- Stage 2: Phase 1 sweep ---
        phase1_probes = self.generator.generate_phase1_probes()
        phase1_outcomes = self.executor.run(phase1_probes)
        results["phase1_outcomes"] = phase1_outcomes
        results["total_probes_run"] += len(phase1_probes)
        phase1_flagged = {
            o.probe.src_user for o in phase1_outcomes
            if o.result == ProbeResult.FAIL
        }

        if verbose:
            print()
            print("=" * 65)
            print("STAGE 2: PHASE 1 SWEEP (O(N) isolation check)")
            print("=" * 65)
            self.reporter.report(phase1_outcomes)

        # Merge Phase 1 failures + static checker flagged users for Phase 2.
        # MISSING_RULE and DUPLICATE_RULE, NARROW_RULES are excluded from static_flagged
        # (see StaticCheckResult.flagged_users) — they don't cause isolation
        # failures so there's nothing for Phase 2 to localise.
        users_with_leaks = list(phase1_flagged | static_flagged)
        results["users_with_leaks"] = users_with_leaks

        if verbose:
            if phase1_flagged:
                print(f"\n→ Phase 1 leak detected for: {sorted(phase1_flagged)}")
            if static_flagged:
                print(f"→ Static checker escalated:  {sorted(static_flagged)}")
            if users_with_leaks:
                print(f"→ Triggering Phase 2 for {len(users_with_leaks)} user(s)...")
            else:
                print("\n→ No leaks detected. Phase 2 not needed.")

        # --- Stage 3: Phase 2 localisation ---
        phase2_flagged = set()
        if users_with_leaks:
            phase2_probes = self.generator.generate_phase2_probes(users_with_leaks)
            phase2_outcomes = self.executor.run(phase2_probes)
            results["phase2_outcomes"] = phase2_outcomes
            results["total_probes_run"] += len(phase2_probes)
            phase2_flagged = {
                o.probe.src_user for o in phase2_outcomes
                if o.result == ProbeResult.FAIL
            }

            if verbose:
                print()
                print("=" * 65)
                print("STAGE 3: PHASE 2 LOCALISATION (targeted boundary testing)")
                print("=" * 65)
                self.reporter.report(phase2_outcomes)

        # --- Final summary ---
        if verbose:
            print()
            print("=" * 65)
            print("PIPELINE SUMMARY")
            print("=" * 65)
            print(f"Total probes run:        {results['total_probes_run']}")
            print(f"  Positive probes:       {len(positive_probes)}")
            print(f"  Phase 1 probes:        {len(phase1_probes)}")
            print(f"  Phase 2 probes:        {len(results['phase2_outcomes'])}")
            print()
            print(f"Static violations:       {len(static_result.violations)}")
            print(f"Reachability failures:   {len(positive_failure_users)}")
            print(f"Isolation violations:    {len(phase2_flagged)}")
            print()

            any_violations = static_result.violations or positive_failure_users or phase2_flagged
            if not any_violations:
                print("✓ ACL correctly enforces isolation and reachability. No violations found.")
            else:
                affected = positive_failure_users | phase2_flagged
                if static_result.violations and not affected:
                    print("⚠️  Static violations found but no probe failures detected.")
                    print("   Likely cause: flagged rule(s) cover unallocated or inactive subnets.")
                else:
                    print(f"✗ Violations detected. Review ACL rules for: {sorted(affected)}")
                print()
                print("Note: ORPHAN_RULE and DUPLICATE_RULES are reported in the static")
                print("      check above — they don't affect isolation but should be cleaned up.")

        return results


if __name__ == "__main__":
    from synthetic_data.generator import generate_synthetic_db
    from acl_generator.generator import ACLGenerator

    db = generate_synthetic_db(num_students=5, num_instructors=1)
    policy = ACLGenerator(db).generate()

    print("=" * 65)
    print("TEST 1: Clean policy — Phase 2 should never trigger")
    print("=" * 65)
    TwoPhasePipeline(policy, db).run()

    print()
    print("=" * 65)
    print("TEST 2: Privilege Escalation rule — student2 gets full management subnet")
    print("=" * 65)
    faulty = copy.deepcopy(policy)
    for rule in faulty.acls:
        if len(rule.src) == 1 and rule.src[0] == "student2@":
            rule.dst = ["10.20.0.0/16:*"]
    TwoPhasePipeline(faulty, db).run()

    print()
    print("=" * 65)
    print("TEST 3: Wrong subnet — student1 points to student2's subnet")
    print("=" * 65)
    faulty3 = copy.deepcopy(policy)
    for rule in faulty3.acls:
        if len(rule.src) == 1 and rule.src[0] == "student1@":
            rule.dst = ["10.20.3.0/24:*"]
    TwoPhasePipeline(faulty3, db).run()

    print()
    print("=" * 65)
    print("TEST 4: Narrow rule - student1 points to its own subnet partially")
    print("=" * 65)
    faulty4 = copy.deepcopy(policy)
    for rule in faulty4.acls:
        if len(rule.src) == 1 and rule.src[0] == "student1@":
            rule.dst = ["10.20.2.128/30:*"]
    TwoPhasePipeline(faulty4, db).run()