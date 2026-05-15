"""
Tests for PolicyAwareExecutor (the oracle).

Validates that the oracle correctly models Headscale's ACL semantics:
  - Deny by default (no matching rule → deny)
  - First-match accept
  - CIDR containment (dst IP inside dst subnet → match)
  - Port matching (* wildcard, specific ports, ICMP port-0)
  - Wildcard src (*) matches all users
  - Per-user src (username@) matches only that user

Fault injection tests: each ACL misconfiguration type from the real world
is injected and the oracle must flag the correct probes as FAIL.

No network access. No SSH. No Headscale.
"""

import copy
import pytest

from probe_executor.policy_executor import PolicyAwareExecutor, ProbeResult
from models.policy import ACLRule, HeadscalePolicy
from tests.helpers import make_probe, set_dst_for, remove_rule_for


# ── Helpers ────────────────────────────────────────────────────────────────────

def run_single(policy, src_user, dst_ip, dst_port=0, expected=True, phase=0):
    probe = make_probe(src_user, dst_ip, dst_port=dst_port,
                       expected=expected, phase=phase)
    return PolicyAwareExecutor(policy).evaluate_probe(probe)


# ── Deny by default ────────────────────────────────────────────────────────────

class TestDenyByDefault:
    def test_empty_policy_denies_everything(self):
        policy = HeadscalePolicy(tag_owners={}, acls=[], auto_approvers={})
        outcome = run_single(policy, "student1", "10.20.2.10", expected=False)
        assert outcome.result == ProbeResult.PASS
        assert outcome.observed is False
        assert outcome.matched_rule == -1

    def test_no_matching_rule_denies(self, policy, db):
        """A probe for a user with no ACL rule must be denied."""
        outcome = run_single(policy, "no_such_user", "10.20.2.10", expected=False)
        assert outcome.result == ProbeResult.PASS
        assert outcome.observed is False


# ── Per-user rule matching ─────────────────────────────────────────────────────

class TestPerUserRuleMatching:
    def test_user_can_reach_own_subnet(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet = db.get_subnet_for_user(student.id).subnet_cidr
        dst_ip = subnet.replace(".0/24", ".10")

        outcome = run_single(policy, student.headscale_username, dst_ip, expected=True)
        assert outcome.result == ProbeResult.PASS
        assert outcome.observed is True

    def test_user_cannot_reach_other_tenants_subnet(self, db, policy):
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        s1, s2 = students[0], students[1]
        s2_subnet = db.get_subnet_for_user(s2.id).subnet_cidr
        dst_ip = s2_subnet.replace(".0/24", ".10")

        outcome = run_single(policy, s1.headscale_username, dst_ip, expected=False)
        assert outcome.result == ProbeResult.PASS
        assert outcome.observed is False

    def test_rule_only_matches_named_user(self, db, policy):
        """student1's rule must not grant student2 access to student1's subnet."""
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        s1, s2 = students[0], students[1]
        s1_subnet = db.get_subnet_for_user(s1.id).subnet_cidr
        dst_ip = s1_subnet.replace(".0/24", ".10")

        outcome = run_single(policy, s2.headscale_username, dst_ip, expected=False)
        assert outcome.result == ProbeResult.PASS
        assert outcome.observed is False


# ── CIDR matching ──────────────────────────────────────────────────────────────

class TestCIDRMatching:
    def test_first_ip_in_subnet_matches(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet_base = db.get_subnet_for_user(student.id).subnet_cidr.split("/")[0]
        # .1 is the first usable host
        dst_ip = subnet_base[:-1] + "1"

        outcome = run_single(policy, student.headscale_username, dst_ip, expected=True)
        assert outcome.result == ProbeResult.PASS

    def test_last_ip_in_subnet_matches(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet_base = db.get_subnet_for_user(student.id).subnet_cidr.split("/")[0]
        dst_ip = subnet_base[:-1] + "254"

        outcome = run_single(policy, student.headscale_username, dst_ip, expected=True)
        assert outcome.result == ProbeResult.PASS

    def test_ip_outside_subnet_does_not_match(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        # An IP in a completely different /24
        outcome = run_single(policy, student.headscale_username, "192.168.1.10", expected=False)
        assert outcome.result == ProbeResult.PASS
        assert outcome.observed is False


# ── Port matching ──────────────────────────────────────────────────────────────

class TestPortMatching:
    def test_wildcard_port_allows_any_port(self, db, policy):
        """All generated rules use dst:*, so any port must match."""
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet_ip = db.get_subnet_for_user(student.id).subnet_cidr.replace(".0/24", ".10")

        for port in [0, 22, 80, 443, 8080, 65535]:
            outcome = run_single(policy, student.headscale_username,
                                 subnet_ip, dst_port=port, expected=True)
            assert outcome.result == ProbeResult.PASS, f"Port {port} should be allowed"

    def test_specific_port_rule_allows_only_that_port(self, db):
        """Rule with dst=10.20.2.0/24:22 — only port 22 allowed."""
        from models.policy import HeadscalePolicy
        policy = HeadscalePolicy(
            tag_owners={},
            acls=[ACLRule(action="accept", src=["student1@"], dst=["10.20.2.0/24:22"])],
            auto_approvers={},
        )
        allowed = run_single(policy, "student1", "10.20.2.10", dst_port=22, expected=True)
        assert allowed.result == ProbeResult.PASS
        assert allowed.observed is True

        denied = run_single(policy, "student1", "10.20.2.10", dst_port=80, expected=False)
        assert denied.result == ProbeResult.PASS
        assert denied.observed is False

    def test_icmp_port_zero_matches_wildcard_rule(self, db, policy):
        """ICMP probes use port=0, which must match wildcard dst:* rules."""
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet_ip = db.get_subnet_for_user(student.id).subnet_cidr.replace(".0/24", ".10")

        outcome = run_single(policy, student.headscale_username,
                             subnet_ip, dst_port=0, expected=True)
        assert outcome.result == ProbeResult.PASS

    def test_comma_separated_ports(self, db):
        """dst=10.20.2.0/24:22,443 — both ports allowed, others denied."""
        policy = HeadscalePolicy(
            tag_owners={},
            acls=[ACLRule(action="accept", src=["student1@"],
                          dst=["10.20.2.0/24:22,443"])],
            auto_approvers={},
        )
        for port, should_allow in [(22, True), (443, True), (80, False), (8080, False)]:
            outcome = run_single(policy, "student1", "10.20.2.10",
                                 dst_port=port, expected=should_allow)
            assert outcome.result == ProbeResult.PASS, \
                f"Port {port}: expected allow={should_allow}, got {outcome.observed}"


# ── Wildcard src ───────────────────────────────────────────────────────────────

class TestWildcardSrc:
    def test_wildcard_src_matches_any_user(self):
        policy = HeadscalePolicy(
            tag_owners={},
            acls=[ACLRule(action="accept", src=["*"], dst=["10.20.2.0/24:*"])],
            auto_approvers={},
        )
        for user in ["student1", "student2", "instructor1", "anyone"]:
            outcome = run_single(policy, user, "10.20.2.10", expected=True)
            assert outcome.result == ProbeResult.PASS, f"User {user} should be allowed"


# ── Fault injection ────────────────────────────────────────────────────────────

class TestFaultInjection:
    def test_missing_rule_causes_reachability_failure(self, db, policy):
        """Remove student's rule → their positive probe (expected=ALLOW) fails."""
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet_ip = db.get_subnet_for_user(student.id).subnet_cidr.replace(".0/24", ".10")

        faulty = remove_rule_for(student.headscale_username, policy)
        outcome = run_single(faulty, student.headscale_username, subnet_ip, expected=True)

        assert outcome.result == ProbeResult.FAIL
        assert outcome.observed is False

    def test_overly_broad_rule_allows_cross_tenant_access(self, db, policy):
        """student1 gets /16 rule → can reach student2's subnet (expected=DENY, observed=ALLOW)."""
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        s1, s2 = students[0], students[1]
        s2_subnet_ip = db.get_subnet_for_user(s2.id).subnet_cidr.replace(".0/24", ".10")

        faulty = set_dst_for(s1.headscale_username, ["10.20.0.0/16:*"], policy)

        # Negative probe: s1 → s2's IP, expected=DENY
        outcome = run_single(faulty, s1.headscale_username,
                             s2_subnet_ip, expected=False, phase=1)
        assert outcome.result == ProbeResult.FAIL
        assert outcome.observed is True  # observed ALLOW — isolation leak

    def test_wrong_subnet_denies_own_reachability(self, db, policy):
        """student1 points to a non-existent subnet → can't reach their own subnet."""
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        own_subnet_ip = db.get_subnet_for_user(student.id).subnet_cidr.replace(".0/24", ".10")

        faulty = set_dst_for(student.headscale_username, ["10.20.99.0/24:*"], policy)

        outcome = run_single(faulty, student.headscale_username,
                             own_subnet_ip, expected=True)
        assert outcome.result == ProbeResult.FAIL
        assert outcome.observed is False

    def test_wrong_subnet_pointing_to_another_tenant(self, db, policy):
        """student1 points to student2's subnet → s1 can reach s2 (isolation violation)."""
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        s1, s2 = students[0], students[1]
        s2_subnet = db.get_subnet_for_user(s2.id).subnet_cidr
        s2_subnet_ip = s2_subnet.replace(".0/24", ".10")

        faulty = set_dst_for(s1.headscale_username, [f"{s2_subnet}:*"], policy)

        # s1 → s2's IP, expected=DENY — but ACL allows it
        outcome = run_single(faulty, s1.headscale_username,
                             s2_subnet_ip, expected=False, phase=1)
        assert outcome.result == ProbeResult.FAIL
        assert outcome.observed is True

    def test_narrow_rule_pointing_to_own_subnet_partially(self, db, policy):
        """ student2 points to its own subnet partially - reachability violation - should be caught by one of its positive probe for all narrow cases """
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        s1 = students[0]
        s1_subnet = db.get_subnet_for_user(s1.id).subnet_cidr
        s1_subnet_modified = s1_subnet.replace(".0/24", ".0/28")

        faulty = set_dst_for(s1.headscale_username, [f"{s1_subnet_modified}:*"], policy)
        ip1 = s1_subnet.replace(".0/24", ".200")
        outcome = run_single(faulty, s1.headscale_username, ip1, expected=True, phase=0)

        assert outcome.result == ProbeResult.FAIL
        assert outcome.observed is False

    def test_clean_policy_all_probes_pass(self, db, policy, user_subnet_map):
        """Full two-phase probe set against clean policy — every probe must PASS."""
        from probe_generator.two_phase_generator import TwoPhaseProbeGenerator

        gen = TwoPhaseProbeGenerator(user_subnet_map)
        probe_set = gen.generate(users_with_leaks=[])
        executor = PolicyAwareExecutor(policy)

        outcomes = executor.run(probe_set.positive_probes + probe_set.phase1_probes)
        failed = [o for o in outcomes if o.result == ProbeResult.FAIL]

        assert failed == [], \
            f"{len(failed)} probe(s) failed on clean policy:\n" + \
            "\n".join(str(o) for o in failed)