"""
Two-Phase Adaptive Probe Generator.

Phase 1 — O(N) sweep:
  For each user, send one negative probe to any other tenant's subnet.
  Identifies WHICH users have an isolation leak, cheaply.

Phase 2 — Targeted localisation:
  Only for users who failed Phase 1, send N-1 directed probes
  to identify exactly WHICH boundary is violated.

Probe counts:
  Positive:        2N  (ICMP + TCP:22 per user)
  Phase 1 neg:     N   (one per user)
  Phase 2 neg:     k(N-1) where k = number of users who failed Phase 1
  ---
  Best case:       2N + N = 3N      (no violations, Phase 2 never runs)
  Worst case:      2N + N + N(N-1)  (all users violated)
  Typical case:    2N + N + k(N-1)  (k violations, k << N)
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from acl_generator.generator import HeadscalePolicy


@dataclass
class Probe:
    src_user: str
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    expected: bool
    phase: int = 0          # 0=positive, 1=phase1 sweep, 2=phase2 localisation
    rule_index: Optional[int] = None
    description: str = ""

    def __str__(self):
        verdict = "ALLOW" if self.expected else "DENY"
        phase_str = f"[P{self.phase}]" if self.phase > 0 else "[+]"
        return (f"{phase_str} [{verdict}] {self.src_user} {self.src_ip} -> "
                f"{self.dst_ip}:{self.dst_port}/{self.proto} | {self.description}")


@dataclass
class TwoPhaseProbeSet:
    positive_probes: list = field(default_factory=list)
    phase1_probes: list = field(default_factory=list)
    # Phase 2 probes are generated dynamically after Phase 1 results
    # but we pre-generate them here for the mock evaluation
    phase2_probes: list = field(default_factory=list)

    @property
    def all_probes(self):
        return self.positive_probes + self.phase1_probes + self.phase2_probes

    def summarize(self, n_users: int) -> None:
        naive_exhaustive = 254 * 254 * n_users * (n_users - 1)
        our_worst_case = len(self.positive_probes) + len(self.phase1_probes) + len(self.phase2_probes)

        print(f"Two-Phase Probe Set Summary")
        print(f"{'=' * 55}")
        print(f"Users/tenants (N):         {n_users}")
        print(f"Positive probes (2N):      {len(self.positive_probes)}")
        print(f"Phase 1 probes (N):        {len(self.phase1_probes)}")
        print(f"Phase 2 probes k(N-1):     {len(self.phase2_probes)}")
        print(f"Total (this run):          {our_worst_case}")
        print(f"Naive exhaustive (H²×N(N-1)): {naive_exhaustive:,}")
        print(f"Reduction factor:          {naive_exhaustive / max(our_worst_case, 1):,.0f}x")
        print()
        print(f"Best case  (k=0): {len(self.positive_probes) + len(self.phase1_probes)} probes (3N)")
        print(f"Worst case (k=N): {len(self.positive_probes) + len(self.phase1_probes) + n_users * (n_users - 1)} probes (2N + N(N-1))")


class TwoPhaseProbeGenerator:
    HOST_OFFSET = 10

    def __init__(self, policy: HeadscalePolicy, user_subnet_map: dict):
        self.policy = policy
        self.user_subnet_map = user_subnet_map

    def _representative_ip(self, subnet_cidr: str) -> str:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        return str(network.network_address + self.HOST_OFFSET)

    def _src_ip_for_user(self, username: str) -> str:
        subnet = self.user_subnet_map.get(username)
        return self._representative_ip(subnet) if subnet else "0.0.0.0"

    def _extract_username(self, src_entry: str) -> Optional[str]:
        return src_entry[:-1] if src_entry.endswith("@") else None

    def _extract_subnet(self, dst_entry: str) -> Optional[str]:
        return dst_entry.rsplit(":", 1)[0] if ":" in dst_entry else dst_entry

    def _get_user_subnets(self) -> list:
        """Returns list of (username, subnet) pairs from ACL rules."""
        user_subnets = []
        for rule in self.policy.acls:
            if rule.action != "accept":
                continue
            for src_entry in rule.src:
                username = self._extract_username(src_entry)
                if not username:
                    continue
                for dst_entry in rule.dst:
                    subnet = self._extract_subnet(dst_entry)
                    if subnet:
                        user_subnets.append((username, subnet))
        return user_subnets

    def generate_positive_probes(self) -> list:
        """2N positive probes — one ICMP + one TCP:22 per user."""
        probes = []
        for i, rule in enumerate(self.policy.acls):
            if rule.action != "accept":
                continue
            for src_entry in rule.src:
                username = self._extract_username(src_entry)
                if not username:
                    continue
                src_ip = self._src_ip_for_user(username)
                for dst_entry in rule.dst:
                    subnet = self._extract_subnet(dst_entry)
                    if not subnet:
                        continue
                    dst_ip = self._representative_ip(subnet)
                    probes.append(Probe(
                        src_user=username, src_ip=src_ip, dst_ip=dst_ip,
                        dst_port=0, proto="icmp", expected=True, phase=0,
                        rule_index=i,
                        description=f"{username} -> own subnet {subnet} (should allow)"
                    ))
                    probes.append(Probe(
                        src_user=username, src_ip=src_ip, dst_ip=dst_ip,
                        dst_port=22, proto="tcp", expected=True, phase=0,
                        rule_index=i,
                        description=f"{username} -> own subnet {subnet}:22 (should allow)"
                    ))
        return probes

    def generate_phase1_probes(self) -> list:
        """
        N Phase 1 probes — one per user to ANY other tenant's subnet.
        Cheap O(N) sweep to detect which users have isolation leaks.
        We pick the next user's subnet as the probe target (arbitrary but consistent).
        """
        probes = []
        user_subnets = self._get_user_subnets()

        for i, (username, own_subnet) in enumerate(user_subnets):
            # Pick any other subnet — use next one in list (wrapping)
            other_idx = (i + 1) % len(user_subnets)
            other_user, other_subnet = user_subnets[other_idx]

            src_ip = self._src_ip_for_user(username)
            dst_ip = self._representative_ip(other_subnet)

            probes.append(Probe(
                src_user=username, src_ip=src_ip, dst_ip=dst_ip,
                dst_port=0, proto="icmp", expected=False, phase=1,
                description=f"{username} -> {other_subnet} (isolation sweep, should deny)"
            ))

        return probes

    def generate_phase2_probes(self, users_with_leaks: list) -> list:
        """
        Phase 2 — k(N-1) targeted probes.
        Only generated for users who failed Phase 1.
        Tests ALL other subnets to localise exactly which boundary is violated.
        """
        probes = []
        user_subnets = self._get_user_subnets()
        all_users = {u for u, _ in user_subnets}

        for leaking_user in users_with_leaks:
            src_ip = self._src_ip_for_user(leaking_user)
            leaking_user_subnet = self.user_subnet_map.get(leaking_user)

            for other_user, other_subnet in user_subnets:
                if other_user == leaking_user:
                    continue
                # Skip the probe we already ran in Phase 1 for this user
                # (we already know they can reach at least one subnet)
                dst_ip = self._representative_ip(other_subnet)
                probes.append(Probe(
                    src_user=leaking_user, src_ip=src_ip, dst_ip=dst_ip,
                    dst_port=0, proto="icmp", expected=False, phase=2,
                    description=f"{leaking_user} -> {other_subnet} (localisation, should deny)"
                ))

        return probes

    def generate(self, users_with_leaks: list = None) -> TwoPhaseProbeSet:
        """
        Generate the full two-phase probe set.
        If users_with_leaks is None, pre-generates Phase 2 for all users
        (useful for mock evaluation). In real execution, Phase 2 is only
        generated after Phase 1 results are known.
        """
        positive = self.generate_positive_probes()
        phase1 = self.generate_phase1_probes()
        phase2 = self.generate_phase2_probes(users_with_leaks or [])

        return TwoPhaseProbeSet(
            positive_probes=positive,
            phase1_probes=phase1,
            phase2_probes=phase2
        )


if __name__ == "__main__":
    from synthetic_data.generator import generate_synthetic_db
    from acl_generator.generator import ACLGenerator

    db = generate_synthetic_db(num_students=5, num_instructors=1)
    policy = ACLGenerator(db).generate()

    user_subnet_map = {}
    for user in db.get_active_users():
        subnet = db.get_subnet_for_user(user.id)
        if subnet:
            user_subnet_map[user.headscale_username] = subnet.subnet_cidr

    gen = TwoPhaseProbeGenerator(policy, user_subnet_map)

    print("=== No violations (Phase 2 never triggered) ===")
    probe_set = gen.generate(users_with_leaks=[])
    probe_set.summarize(len(user_subnet_map))

    print()
    print("=== 2 users have leaks (Phase 2 triggered for them) ===")
    probe_set_2 = gen.generate(users_with_leaks=["student1", "student2"])
    probe_set_2.summarize(len(user_subnet_map))

    print()
    print("=== All users have leaks (worst case) ===")
    probe_set_all = gen.generate(users_with_leaks=list(user_subnet_map.keys()))
    probe_set_all.summarize(len(user_subnet_map))