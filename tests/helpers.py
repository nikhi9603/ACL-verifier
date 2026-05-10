"""
Shared test helper functions for the CyberRange ACL Verifier test suite.

Import these directly in test files:
    from tests.helpers import make_probe, set_dst_for, remove_rule_for, rule_for
"""

import copy
from models.policy import HeadscalePolicy, ACLRule


def make_probe(src_user, dst_ip, dst_port=0, proto="icmp",
               expected=True, phase=0, dst_user=None, description=""):
    """Convenience factory so tests don't have to import Probe directly."""
    from probe_generator.two_phase_generator import Probe
    return Probe(
        src_user=src_user,
        src_ip="0.0.0.0",   # not used by oracle
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        expected=expected,
        phase=phase,
        dst_user=dst_user or src_user,
        description=description,
    )


def rule_for(username: str, policy: HeadscalePolicy) -> ACLRule | None:
    """Return the first ACL rule whose src matches username@, or None."""
    for rule in policy.acls:
        if any(s == f"{username}@" for s in rule.src):
            return rule
    return None


def remove_rule_for(username: str, policy: HeadscalePolicy) -> HeadscalePolicy:
    """Return a deep copy of policy with all rules for username@ removed."""
    p = copy.deepcopy(policy)
    p.acls = [r for r in p.acls if f"{username}@" not in r.src]
    return p


def set_dst_for(username: str, new_dst: list[str],
                policy: HeadscalePolicy) -> HeadscalePolicy:
    """Return a deep copy of policy with username@'s dst replaced."""
    p = copy.deepcopy(policy)
    for rule in p.acls:
        if f"{username}@" in rule.src:
            rule.dst = new_dst
    return p