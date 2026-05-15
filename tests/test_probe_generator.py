"""
Tests for TwoPhaseProbeGenerator.

Validates:
  - Correct probe counts (4N positive, 2N phase1, 2k(N-1) phase2)
  - Probe structure (phase tags, expected flags, src/dst assignment)
  - Probes are generated from DB ground truth, NOT from the ACL
  - N=1 edge case: Phase 1 must return empty (no other tenant to probe against)
  - Phase 2 only runs for users in users_with_leaks
  - Probe independence: a wrong ACL does not change which probes are generated

No network access. No SSH. No Headscale.
"""

import copy
from ipaddress import ip_network
import pytest

from probe_generator.two_phase_generator import TwoPhaseProbeGenerator, Probe
from tests.helpers import set_dst_for


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_gen(policy, user_subnet_map) -> TwoPhaseProbeGenerator:
    return TwoPhaseProbeGenerator(user_subnet_map)


# ── Probe counts ───────────────────────────────────────────────────────────────

class TestProbeCounts:
    def test_positive_probe_count_is_4n(self, policy, user_subnet_map):
        """2 IPs × (ICMP + TCP:22) × N users = 4N positive probes."""
        n = len(user_subnet_map)
        gen = make_gen(policy, user_subnet_map)
        assert len(gen.generate_positive_probes()) == 4 * n

    def test_phase1_probe_count_is_2n(self, policy, user_subnet_map):
        """2 representative IPs per tenant × N users = 2N Phase 1 probes."""
        n = len(user_subnet_map)
        gen = make_gen(policy, user_subnet_map)
        assert len(gen.generate_phase1_probes()) == 2 * n

    def test_phase2_probe_count_is_2k_times_n_minus_1(self, policy, user_subnet_map):
        """2 IPs per target subnet × k leaking users × (N-1) other subnets."""
        n = len(user_subnet_map)
        users = list(user_subnet_map.keys())

        for k in range(0, n + 1):
            leaking = users[:k]
            gen = make_gen(policy, user_subnet_map)
            phase2 = gen.generate_phase2_probes(leaking)
            assert len(phase2) == 2 * k * (n - 1), \
                f"k={k}, n={n}: expected {2*k*(n-1)} phase2 probes, got {len(phase2)}"

    def test_best_case_total_is_6n(self, policy, user_subnet_map):
        """Best case (no violations): 4N + 2N = 6N probes."""
        n = len(user_subnet_map)
        gen = make_gen(policy, user_subnet_map)
        probe_set = gen.generate(users_with_leaks=[])
        assert len(probe_set.all_probes) == 6 * n

    def test_worst_case_total(self, policy, user_subnet_map):
        """Worst case (all violated): 4N + 2N + 2N(N-1) probes."""
        n = len(user_subnet_map)
        gen = make_gen(policy, user_subnet_map)
        probe_set = gen.generate(users_with_leaks=list(user_subnet_map.keys()))
        expected_total = 4 * n + 2 * n + 2 * n * (n - 1)
        assert len(probe_set.all_probes) == expected_total


# ── N=1 edge case ──────────────────────────────────────────────────────────────

class TestSingleTenantEdgeCase:
    def test_phase1_empty_for_n_equals_1(self):
        """With only one tenant, there's no other subnet to sweep against."""
        from synthetic_data.generator import generate_synthetic_db
        from acl_generator.generator import ACLGenerator

        db1 = generate_synthetic_db(num_students=1, num_instructors=0)
        policy1 = ACLGenerator(db1).generate()
        user_subnet_map1 = {
            u.headscale_username: db1.get_subnet_for_user(u.id).subnet_cidr
            for u in db1.get_active_users()
        }

        gen = make_gen(policy1, user_subnet_map1)
        assert gen.generate_phase1_probes() == []

    def test_positive_probes_still_generated_for_n_equals_1(self):
        from synthetic_data.generator import generate_synthetic_db
        from acl_generator.generator import ACLGenerator

        db1 = generate_synthetic_db(num_students=1, num_instructors=0)
        policy1 = ACLGenerator(db1).generate()
        user_subnet_map1 = {
            u.headscale_username: db1.get_subnet_for_user(u.id).subnet_cidr
            for u in db1.get_active_users()
        }

        gen = make_gen(policy1, user_subnet_map1)
        assert len(gen.generate_positive_probes()) == 4  # 4N = 4×1


# ── Probe structure ────────────────────────────────────────────────────────────

class TestProbeStructure:
    def test_positive_probes_are_phase_0(self, policy, user_subnet_map):
        gen = make_gen(policy, user_subnet_map)
        for probe in gen.generate_positive_probes():
            assert probe.phase == 0

    def test_positive_probes_expected_true(self, policy, user_subnet_map):
        gen = make_gen(policy, user_subnet_map)
        for probe in gen.generate_positive_probes():
            assert probe.expected is True

    def test_positive_probes_src_equals_dst_user(self, policy, user_subnet_map):
        gen = make_gen(policy, user_subnet_map)
        for probe in gen.generate_positive_probes():
            assert probe.src_user == probe.dst_user

    def test_phase1_probes_are_phase_1(self, policy, user_subnet_map):
        gen = make_gen(policy, user_subnet_map)
        for probe in gen.generate_phase1_probes():
            assert probe.phase == 1

    def test_phase1_probes_expected_false(self, policy, user_subnet_map):
        gen = make_gen(policy, user_subnet_map)
        for probe in gen.generate_phase1_probes():
            assert probe.expected is False

    def test_phase1_probes_src_not_equal_dst_user(self, policy, user_subnet_map):
        """Phase 1 sweeps to a different tenant — src and dst must differ."""
        gen = make_gen(policy, user_subnet_map)
        for probe in gen.generate_phase1_probes():
            assert probe.src_user != probe.dst_user

    def test_phase2_probes_are_phase_2(self, policy, user_subnet_map):
        gen = make_gen(policy, user_subnet_map)
        users = list(user_subnet_map.keys())
        for probe in gen.generate_phase2_probes([users[0]]):
            assert probe.phase == 2

    def test_phase2_probes_expected_false(self, policy, user_subnet_map):
        gen = make_gen(policy, user_subnet_map)
        users = list(user_subnet_map.keys())
        for probe in gen.generate_phase2_probes([users[0]]):
            assert probe.expected is False

    def test_positive_probes_include_icmp_and_tcp22(self, policy, user_subnet_map):
        """Each user gets 4 positive probes: ICMP+TCP:22 at .10, ICMP+TCP:22 at .200."""
        gen = make_gen(policy, user_subnet_map)
        probes = gen.generate_positive_probes()
        for username in user_subnet_map:
            user_probes = [p for p in probes if p.src_user == username]
            assert len(user_probes) == 4
            protos = {p.proto for p in user_probes}
            ports  = {p.dst_port for p in user_probes}
            assert "icmp" in protos
            assert "tcp" in protos
            assert 22 in ports

    def test_phase1_each_user_probes_different_tenant(self, policy, user_subnet_map):
        """Each Phase 1 probe must target a different user's subnet, not the user's own."""
        gen = make_gen(policy, user_subnet_map)
        for probe in gen.generate_phase1_probes():
            own_subnet = user_subnet_map[probe.src_user]
            own_ip = own_subnet.rsplit(".", 1)[0] + ".10"
            assert probe.dst_ip != own_ip, \
                f"{probe.src_user}'s Phase 1 probe targets their own subnet"


# ── ACL independence ───────────────────────────────────────────────────────────

class TestACLIndependence:
    """
    Core invariant: probes are generated from DB ground truth (user_subnet_map),
    NOT from the ACL. A broken ACL must not change which probes are generated.
    """

    def test_broken_acl_does_not_change_probe_set(self, db, policy, user_subnet_map):
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        s1 = students[0]

        # Break the ACL for s1
        faulty = set_dst_for(s1.headscale_username, ["10.20.99.0/24:*"], policy)

        gen_clean  = make_gen(policy, user_subnet_map)
        gen_faulty = make_gen(faulty, user_subnet_map)

        clean_set  = gen_clean.generate(users_with_leaks=[])
        faulty_set = gen_faulty.generate(users_with_leaks=[])

        # Same number of probes
        assert len(clean_set.all_probes) == len(faulty_set.all_probes)

        # Same dst IPs — the broken ACL must not redirect probes
        clean_dsts  = sorted(p.dst_ip for p in clean_set.all_probes)
        faulty_dsts = sorted(p.dst_ip for p in faulty_set.all_probes)
        assert clean_dsts == faulty_dsts

    def test_probe_dst_ips_come_from_db_not_acl(self, db, policy, user_subnet_map):
        """
        Every probe dst_ip must be the .10 representative of a subnet in
        user_subnet_map (DB), never from the ACL's dst CIDRs.
        """
        valid_ips = {
            str(ip_network(cidr, strict=False).network_address + offset)
            for cidr in user_subnet_map.values()
            for offset in [10, 200]
        }
        gen = make_gen(policy, user_subnet_map)
        probe_set = gen.generate(users_with_leaks=list(user_subnet_map.keys()))

        for probe in probe_set.all_probes:
            assert probe.dst_ip in valid_ips, \
                f"Probe dst {probe.dst_ip} not derived from DB subnet map"


# ── Phase 2 only for leaking users ────────────────────────────────────────────

class TestPhase2Targeting:
    def test_phase2_only_generates_for_specified_users(self, policy, user_subnet_map):
        users = list(user_subnet_map.keys())
        leaking_user = users[0]

        gen = make_gen(policy, user_subnet_map)
        phase2 = gen.generate_phase2_probes([leaking_user])

        src_users = {p.src_user for p in phase2}
        assert src_users == {leaking_user}

    def test_phase2_covers_all_other_tenants(self, policy, user_subnet_map):
        users = list(user_subnet_map.keys())
        leaking_user = users[0]
        other_users = set(users[1:])

        gen = make_gen(policy, user_subnet_map)
        phase2 = gen.generate_phase2_probes([leaking_user])

        dst_users = {p.dst_user for p in phase2}
        assert dst_users == other_users

    def test_phase2_does_not_probe_user_against_themselves(self, policy, user_subnet_map):
        users = list(user_subnet_map.keys())
        gen = make_gen(policy, user_subnet_map)
        phase2 = gen.generate_phase2_probes(users)

        for probe in phase2:
            assert probe.src_user != probe.dst_user, \
                f"Phase 2 probe from {probe.src_user} targets itself"

    def test_phase2_empty_when_no_leaks(self, policy, user_subnet_map):
        gen = make_gen(policy, user_subnet_map)
        assert gen.generate_phase2_probes([]) == []