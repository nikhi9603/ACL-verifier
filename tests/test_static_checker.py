"""
Tests for StaticPolicyChecker.

Covers all 6 violation types:
  MISSING_RULE, WRONG_SUBNET, OVERLY_BROAD_RULE,
  DUPLICATE_RULES, PRIVILEGE_ESCALATION, ORPHAN_RULE

Plus edge cases:
  - Admin users are exempt from per-user rule checks
  - ORPHAN_RULE is excluded from Phase 2 escalation
  - PRIVILEGE_ESCALATION is distinct from OVERLY_BROAD_RULE for non-mgmt /16s
  - Multiple violations can coexist in the same policy
  - N=1 (single tenant) produces no false positives

No network access. No SSH. No Headscale.
"""

import copy
import pytest
import ipaddress

from static_policy_checker.policy_checker import StaticPolicyChecker, ViolationType
from models.policy import ACLRule
from tests.helpers import remove_rule_for, set_dst_for, rule_for


# ── Helpers ────────────────────────────────────────────────────────────────────

def violation_types(result) -> list[ViolationType]:
    return [v.violation_type for v in result.violations]


def usernames_with(result, vtype: ViolationType) -> list[str]:
    return [v.username for v in result.violations if v.violation_type == vtype]


# ── Clean policy ───────────────────────────────────────────────────────────────

class TestCleanPolicy:
    def test_no_violations(self, db, policy):
        result = StaticPolicyChecker(db).check(policy)
        assert result.passed
        assert result.violations == []

    def test_flagged_users_empty(self, db, policy):
        result = StaticPolicyChecker(db).check(policy)
        assert result.flagged_users == []


# ── MISSING_RULE ───────────────────────────────────────────────────────────────

class TestMissingRule:
    def test_one_user_missing(self, db, policy):
        users = db.get_active_users()
        # Pick the first non-admin student
        student = next(u for u in users if u.role == u.role.STUDENT)
        faulty = remove_rule_for(student.headscale_username, policy)

        result = StaticPolicyChecker(db).check(faulty)

        assert ViolationType.MISSING_RULE in violation_types(result)
        assert student.headscale_username in usernames_with(result, ViolationType.MISSING_RULE)

    def test_missing_rule_does_not_escalate_to_phase2(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        faulty = remove_rule_for(student.headscale_username, policy)

        result = StaticPolicyChecker(db).check(faulty)

        assert student.headscale_username not in result.flagged_users

    def test_all_rules_missing(self, db, policy):
        """Every student's rule removed — one MISSING_RULE per student."""
        faulty = copy.deepcopy(policy)
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        for student in students:
            faulty = remove_rule_for(student.headscale_username, faulty)

        result = StaticPolicyChecker(db).check(faulty)

        missing = usernames_with(result, ViolationType.MISSING_RULE)
        assert len(missing) == len(students)

    def test_admin_exempt_from_missing_rule(self, db, policy):
        """
        Admins have a shared rule (src = [admin1@, admin2@, ...]), not per-user rules.
        Removing an admin's individual entry should not produce MISSING_RULE.
        """
        from synthetic_data.generator import generate_synthetic_db
        from acl_generator.generator import ACLGenerator

        db2 = generate_synthetic_db(num_students=2, num_instructors=0)
        # Manually add an admin user
        import uuid
        from models.db_models import User, SubnetAllocation, UserRole
        admin_id = str(uuid.uuid4())
        admin = User(id=admin_id, email="admin@cyberrange.local",
                     name="Admin", role=UserRole.ADMIN)
        db2.users.append(admin)
        db2.subnet_allocations.append(
            SubnetAllocation(user_id=admin_id, subnet_cidr="10.20.99.0/24")
        )

        policy2 = ACLGenerator(db2).generate()
        # Remove the admin rule entirely
        faulty = copy.deepcopy(policy2)
        faulty.acls = [r for r in faulty.acls
                       if "admin@" not in r.src]

        result = StaticPolicyChecker(db2).check(faulty)

        missing_usernames = usernames_with(result, ViolationType.MISSING_RULE)
        assert "admin" not in missing_usernames


# ── WRONG_SUBNET ───────────────────────────────────────────────────────────────

class TestWrongSubnet:
    def test_user_points_to_another_tenants_subnet(self, db, policy):
        users = db.get_active_users()
        students = [u for u in users if u.role.STUDENT == u.role]
        s1, s2 = students[0], students[1]
        s2_subnet = db.get_subnet_for_user(s2.id).subnet_cidr

        faulty = set_dst_for(s1.headscale_username,
                             [f"{s2_subnet}:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)

        assert ViolationType.WRONG_SUBNET in violation_types(result)
        assert s1.headscale_username in usernames_with(result, ViolationType.WRONG_SUBNET)

    def test_wrong_subnet_escalates_to_phase2(self, db, policy):
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        s1, s2 = students[0], students[1]
        s2_subnet = db.get_subnet_for_user(s2.id).subnet_cidr

        faulty = set_dst_for(s1.headscale_username,
                             [f"{s2_subnet}:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)
        assert s1.headscale_username in result.flagged_users

    def test_wrong_subnet_nonexistent_cidr(self, db, policy):
        """User points to a subnet that exists nowhere in the DB."""
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        faulty = set_dst_for(student.headscale_username,
                             ["10.20.99.0/24:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)

        assert ViolationType.WRONG_SUBNET in violation_types(result)

    def test_correct_subnet_no_wrong_subnet_violation(self, db, policy):
        result = StaticPolicyChecker(db).check(policy)
        assert ViolationType.WRONG_SUBNET not in violation_types(result)

    def test_wrong_subnet_with_narrow_rule_violation(self, db, policy):
        """ User points to wrong subnet but with narrow rule i.e. partial reachability - still classified as wrong subnet and not narrow rule """
        users = db.get_active_users()
        students = [u for u in users if u.role.STUDENT == u.role]
        s1, s2 = students[0], students[1]
        s2_subnet = ipaddress.IPv4Network(db.get_subnet_for_user(s2.id).subnet_cidr)
        s2_subnet_address = s2_subnet.network_address
        faulty_prefix_length = 27 # > 24 for narrow rule
        faulty_subnet = ipaddress.ip_network(f"{s2_subnet_address}/{faulty_prefix_length}")
        faulty = set_dst_for(s1.headscale_username, [f"{faulty_subnet}:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)
        assert ViolationType.WRONG_SUBNET in violation_types(result) and not ViolationType.NARROW_RULE in violation_types(result)
        assert s1.headscale_username in usernames_with(result, ViolationType.WRONG_SUBNET)


# ── OVERLY_BROAD_RULE ──────────────────────────────────────────────────────────

class TestOverlyBroadRule:
    def test_user_gets_slash_16(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        # Use a /16 outside the management space to isolate OVERLY_BROAD from PRIVILEGE_ESCALATION
        faulty = set_dst_for(student.headscale_username,
                             ["192.168.0.0/16:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)

        assert ViolationType.OVERLY_BROAD_RULE in violation_types(result)
        assert student.headscale_username in usernames_with(result, ViolationType.OVERLY_BROAD_RULE)

    def test_slash_24_is_not_overly_broad(self, db, policy):
        """Exact /24 — the correct allocation — must not trigger OVERLY_BROAD_RULE."""
        result = StaticPolicyChecker(db).check(policy)
        assert ViolationType.OVERLY_BROAD_RULE not in violation_types(result)

    def test_slash_23_triggers_overly_broad(self, db, policy):
        """One bit wider than /24 — should trigger."""
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        faulty = set_dst_for(student.headscale_username,
                             ["192.168.0.0/23:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)
        assert ViolationType.OVERLY_BROAD_RULE in violation_types(result)


# ── PRIVILEGE_ESCALATION ───────────────────────────────────────────────────────

class TestPrivilegeEscalation:
    def test_student_points_to_management_slash16(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        faulty = set_dst_for(student.headscale_username,
                             ["10.20.0.0/16:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)

        assert ViolationType.PRIVILEGE_ESCALATION in violation_types(result)
        assert student.headscale_username in usernames_with(
            result, ViolationType.PRIVILEGE_ESCALATION)

    def test_privilege_escalation_not_raised_for_slash24_in_mgmt_space(self, db, policy):
        """
        Tenant /24s like 10.20.2.0/24 sit inside the 10.20.0.0/16 management space
        by CIDR containment. This must NOT trigger PRIVILEGE_ESCALATION — they are
        valid per-tenant allocations. The check only fires on prefixes broader than /24.
        """
        result = StaticPolicyChecker(db).check(policy)
        assert ViolationType.PRIVILEGE_ESCALATION not in violation_types(result)

    def test_privilege_escalation_escalates_to_phase2(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        faulty = set_dst_for(student.headscale_username,
                             ["10.20.0.0/16:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)
        assert student.headscale_username in result.flagged_users

    def test_slash16_outside_mgmt_space_is_overly_broad_not_privilege_escalation(
            self, db, policy):
        """
        10.0.0.0/16 is broad but doesn't overlap the management /16 (10.20.0.0/16).
        Should be OVERLY_BROAD_RULE, not PRIVILEGE_ESCALATION.
        """
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        faulty = set_dst_for(student.headscale_username,
                             ["10.0.0.0/16:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)

        vtypes = violation_types(result)
        assert ViolationType.OVERLY_BROAD_RULE in vtypes
        assert ViolationType.PRIVILEGE_ESCALATION not in vtypes


# ── DUPLICATE_RULES ────────────────────────────────────────────────────────────

class TestDuplicateRules:
    def test_user_has_two_rules(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet = db.get_subnet_for_user(student.id).subnet_cidr

        faulty = copy.deepcopy(policy)
        faulty.acls.append(ACLRule(
            action="accept",
            src=[f"{student.headscale_username}@"],
            dst=[f"{subnet}:*"],
        ))

        result = StaticPolicyChecker(db).check(faulty)

        assert ViolationType.DUPLICATE_RULES in violation_types(result)
        assert student.headscale_username in usernames_with(
            result, ViolationType.DUPLICATE_RULES)

    def test_duplicate_rules_does_not_escalate_to_phase2(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet = db.get_subnet_for_user(student.id).subnet_cidr

        faulty = copy.deepcopy(policy)
        faulty.acls.append(ACLRule(
            action="accept",
            src=[f"{student.headscale_username}@"],
            dst=[f"{subnet}:*"],
        ))

        result = StaticPolicyChecker(db).check(faulty)
        assert student.headscale_username not in result.flagged_users


# ── ORPHAN_RULE ────────────────────────────────────────────────────────────────

class TestOrphanRule:
    def test_rule_for_unknown_user(self, db, policy):
        faulty = copy.deepcopy(policy)
        faulty.acls.append(ACLRule(
            action="accept",
            src=["ghost_user@"],
            dst=["10.20.99.0/24:*"],
        ))

        result = StaticPolicyChecker(db).check(faulty)

        assert ViolationType.ORPHAN_RULE in violation_types(result)
        assert "ghost_user" in usernames_with(result, ViolationType.ORPHAN_RULE)

    def test_orphan_rule_not_escalated_to_phase2(self, db, policy):
        """
        ORPHAN_RULE references a username that has no DB entry — no router to SSH into.
        It must be excluded from Phase 2 escalation.
        """
        faulty = copy.deepcopy(policy)
        faulty.acls.append(ACLRule(
            action="accept",
            src=["ghost_user@"],
            dst=["10.20.99.0/24:*"],
        ))

        result = StaticPolicyChecker(db).check(faulty)
        assert "ghost_user" not in result.flagged_users

# ── NARROW_RULE ────────────────────────────────────────────────────────────────
class TestNarrowRule:
    def test_narrow_rule_user_reaching_own_subnet_partially(self, db, policy):
        users = db.get_active_users()
        non_admin_users = [u for u in users if u.role != u.role.ADMIN]
        s1 = non_admin_users[0]
        s1_subnet = ipaddress.IPv4Network(db.get_subnet_for_user(s1.id).subnet_cidr)
        s1_subnet_address = s1_subnet.network_address
        faulty_prefix_length = 30 # > 24 for narrow rule
        faulty_subnet = ipaddress.ip_network(f"{s1_subnet_address}/{faulty_prefix_length}")
        faulty = set_dst_for(s1.headscale_username, [f"{faulty_subnet}:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)
        assert ViolationType.NARROW_RULE in violation_types(result)
        assert s1.headscale_username in usernames_with(result, ViolationType.NARROW_RULE)

    def test_narrow_rule_not_escalate_phase2(self, db, policy):
        """
        Narrow rules are checked after WRONG_SUBNET detection. Remaining cases only reduce to reachability within the tenant's own subnet and are not isolation leaks to escalate to Phase 2
        """
        users = db.get_active_users()
        non_admin_users = [u for u in users if u.role != u.role.ADMIN]
        s1 = non_admin_users[0]
        s1_subnet = ipaddress.IPv4Network(db.get_subnet_for_user(s1.id).subnet_cidr)
        s1_subnet_address = s1_subnet.network_address
        faulty_prefix_length = 30 # > 24 for narrow rule
        faulty_subnet = ipaddress.ip_network(f"{s1_subnet_address}/{faulty_prefix_length}")
        faulty = set_dst_for(s1.headscale_username, [f"{faulty_subnet}:*"], policy)

        result = StaticPolicyChecker(db).check(faulty)
        assert s1.headscale_username not in result.flagged_users

# ── Multiple violations ────────────────────────────────────────────────────────

class TestMultipleViolations:
    def test_wrong_subnet_and_missing_rule_coexist(self, db, policy):
        students = [u for u in db.get_active_users() if u.role.STUDENT == u.role]
        s1, s2, s3 = students[0], students[1], students[2]
        s2_subnet = db.get_subnet_for_user(s2.id).subnet_cidr

        # s1 points to s2's subnet (WRONG_SUBNET); s3's rule is removed (MISSING_RULE)
        faulty = set_dst_for(s1.headscale_username, [f"{s2_subnet}:*"], policy)
        faulty = remove_rule_for(s3.headscale_username, faulty)

        result = StaticPolicyChecker(db).check(faulty)

        vtypes = violation_types(result)
        assert ViolationType.WRONG_SUBNET in vtypes
        assert ViolationType.MISSING_RULE in vtypes
        # WRONG_SUBNET escalates, MISSING_RULE does not
        assert s1.headscale_username in result.flagged_users
        assert s3.headscale_username not in result.flagged_users

    def test_orphan_and_missing_rule_coexist(self, db, policy):
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        faulty = remove_rule_for(student.headscale_username, policy)
        faulty.acls.append(ACLRule(
            action="accept",
            src=["ghost_user@"],
            dst=["10.20.99.0/24:*"],
        ))

        result = StaticPolicyChecker(db).check(faulty)

        vtypes = violation_types(result)
        assert ViolationType.MISSING_RULE in vtypes
        assert ViolationType.ORPHAN_RULE in vtypes
        # Neither MISSING_RULE nor ORPHAN_RULE escalates to Phase 2
        assert student.headscale_username not in result.flagged_users
        assert "ghost_user" not in result.flagged_users


# ── Edge cases ─────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_single_tenant_clean(self):
        """N=1: one student, correct policy — no violations."""
        from synthetic_data.generator import generate_synthetic_db
        from acl_generator.generator import ACLGenerator

        db1 = generate_synthetic_db(num_students=1, num_instructors=0)
        policy1 = ACLGenerator(db1).generate()

        result = StaticPolicyChecker(db1).check(policy1)
        assert result.passed

    def test_empty_acl_all_users_missing(self, db):
        """Empty ACL — every active user should have a MISSING_RULE."""
        from models.policy import HeadscalePolicy
        empty_policy = HeadscalePolicy(tag_owners={}, acls=[], auto_approvers={})
        active_users = db.get_active_users()
        students = [u for u in active_users if u.role.STUDENT == u.role]

        result = StaticPolicyChecker(db).check(empty_policy)

        missing = usernames_with(result, ViolationType.MISSING_RULE)
        for student in students:
            assert student.headscale_username in missing

    def test_deny_rule_not_counted_as_user_rule(self, db, policy):
        """ACL rules with action='deny' must be ignored by the checker."""
        student = next(u for u in db.get_active_users() if u.role.STUDENT == u.role)
        subnet = db.get_subnet_for_user(student.id).subnet_cidr

        faulty = remove_rule_for(student.headscale_username, policy)
        faulty.acls.append(ACLRule(
            action="deny",                         # deny rule — must not count
            src=[f"{student.headscale_username}@"],
            dst=[f"{subnet}:*"],
        ))

        result = StaticPolicyChecker(db).check(faulty)

        # The deny rule must not satisfy the MISSING_RULE check
        assert ViolationType.MISSING_RULE in violation_types(result)
        assert student.headscale_username in usernames_with(result, ViolationType.MISSING_RULE)

    def test_large_n_clean(self):
        """N=20: generated policy should have zero violations."""
        from synthetic_data.generator import generate_synthetic_db
        from acl_generator.generator import ACLGenerator

        db20 = generate_synthetic_db(num_students=19, num_instructors=1)
        policy20 = ACLGenerator(db20).generate()

        result = StaticPolicyChecker(db20).check(policy20)
        assert result.passed, f"Unexpected violations: {result.violations}"