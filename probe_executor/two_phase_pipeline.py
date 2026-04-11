"""
Two-Phase Pipeline.

Orchestrates the full two-phase adaptive probing workflow:
  1. Run positive probes — verify reachability
  2. Run Phase 1 sweep — O(N) isolation check
  3. Identify which users failed Phase 1
  4. Run Phase 2 localisation — only for users who failed Phase 1
  5. Report all violations with precise boundary localisation
"""

import copy
from probe_generator.two_phase_generator import TwoPhaseProbeGenerator, Probe
from probe_executor.policy_executor import PolicyAwareExecutor, ProbeResult, ViolationReporter


class TwoPhasePipeline:

    def __init__(self, policy, user_subnet_map: dict):
        self.policy = policy
        self.user_subnet_map = user_subnet_map
        self.generator = TwoPhaseProbeGenerator(policy, user_subnet_map)
        self.executor = PolicyAwareExecutor(policy)
        self.reporter = ViolationReporter()

    def run(self, verbose: bool = True) -> dict:
        """
        Execute the full two-phase pipeline.
        Returns a summary dict with probe counts and violations found.
        """
        results = {
            "positive_outcomes": [],
            "phase1_outcomes": [],
            "phase2_outcomes": [],
            "users_with_leaks": [],
            "total_probes_run": 0,
        }

        # --- Positive probes ---
        positive_probes = self.generator.generate_positive_probes()
        positive_outcomes = self.executor.run(positive_probes)
        results["positive_outcomes"] = positive_outcomes
        results["total_probes_run"] += len(positive_probes)

        if verbose:
            print("=" * 65)
            print("POSITIVE PROBE RESULTS (reachability verification)")
            print("=" * 65)
            self.reporter.report(positive_outcomes)

        # --- Phase 1 sweep ---
        phase1_probes = self.generator.generate_phase1_probes()
        phase1_outcomes = self.executor.run(phase1_probes)
        results["phase1_outcomes"] = phase1_outcomes
        results["total_probes_run"] += len(phase1_probes)

        # Identify users who failed Phase 1 (isolation leak detected)
        users_with_leaks = [
            o.probe.src_user for o in phase1_outcomes
            if o.result == ProbeResult.FAIL
        ]
        results["users_with_leaks"] = users_with_leaks

        if verbose:
            print()
            print("=" * 65)
            print("PHASE 1 SWEEP RESULTS (O(N) isolation check)")
            print("=" * 65)
            self.reporter.report(phase1_outcomes)
            if users_with_leaks:
                print(f"\n→ Leak detected for: {users_with_leaks}")
                print(f"→ Triggering Phase 2 localisation for {len(users_with_leaks)} user(s)...")
            else:
                print("\n→ No leaks detected. Phase 2 not needed.")

        # --- Phase 2 localisation (only if needed) ---
        if users_with_leaks:
            phase2_probes = self.generator.generate_phase2_probes(users_with_leaks)
            phase2_outcomes = self.executor.run(phase2_probes)
            results["phase2_outcomes"] = phase2_outcomes
            results["total_probes_run"] += len(phase2_probes)

            if verbose:
                print()
                print("=" * 65)
                print("PHASE 2 LOCALISATION RESULTS (targeted boundary testing)")
                print("=" * 65)
                self.reporter.report(phase2_outcomes)

        # --- Final summary ---
        if verbose:
            print()
            print("=" * 65)
            print("PIPELINE SUMMARY")
            print("=" * 65)
            print(f"Total probes run:      {results['total_probes_run']}")
            print(f"  Positive probes:     {len(positive_probes)}")
            print(f"  Phase 1 probes:      {len(phase1_probes)}")
            print(f"  Phase 2 probes:      {len(results['phase2_outcomes'])}")
            print(f"Users with leaks:      {len(users_with_leaks)}")
            if not users_with_leaks:
                print("\n✓ ACL correctly enforces isolation. No violations found.")

        return results


if __name__ == "__main__":
    from synthetic_data.generator import generate_synthetic_db
    from acl_generator.generator import ACLGenerator, ACLRule

    db = generate_synthetic_db(num_students=5, num_instructors=1)
    policy = ACLGenerator(db).generate()

    user_subnet_map = {}
    for user in db.get_active_users():
        subnet = db.get_subnet_for_user(user.id)
        if subnet:
            user_subnet_map[user.headscale_username] = subnet.subnet_cidr

    print("=" * 65)
    print("TEST 1: Clean policy — Phase 2 should never trigger")
    print("=" * 65)
    pipeline = TwoPhasePipeline(policy, user_subnet_map)
    pipeline.run()

    print()
    print("=" * 65)
    print("TEST 2: Overly broad rule — student2 gets full management subnet")
    print("        Phase 1 should catch student2, Phase 2 localises all boundaries")
    print("=" * 65)
    faulty_policy = copy.deepcopy(policy)
    for rule in faulty_policy.acls:
        if len(rule.src) == 1 and rule.src[0] == "student2@":
            rule.dst = ["10.20.0.0/16:*"]
    pipeline2 = TwoPhasePipeline(faulty_policy, user_subnet_map)
    pipeline2.run()

    print()
    print("=" * 65)
    print("TEST 3: Wrong subnet — student1 points to student2's subnet")
    print("        Phase 1 catches student1 via reachability failure on sweep probe")
    print("=" * 65)
    faulty_policy3 = copy.deepcopy(policy)
    for rule in faulty_policy3.acls:
        if len(rule.src) == 1 and rule.src[0] == "student1@":
            rule.dst = ["10.20.3.0/24:*"]
    pipeline3 = TwoPhasePipeline(faulty_policy3, user_subnet_map)
    pipeline3.run()