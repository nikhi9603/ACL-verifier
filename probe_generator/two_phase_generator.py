"""
Two-Phase Adaptive Probe Generator.

Phase 1 — O(N) sweep:
  For each user, send representative negative probes to another tenant's subnet.
  Identifies WHICH users have an isolation leak, cheaply.

Phase 2 — Targeted localisation:
  Only for users who failed Phase 1, send directed probes
  to identify exactly WHICH boundary is violated.

Representative probing:
  Probes use two representative subnet hosts: .10 and .200.
  Their separation guarantees that any sub-/24 narrow rule
  cannot simultaneously permit both addresses.

Probe counts:
  Positive:        4N          (ICMP + TCP:22 to .10 and .200)
  Phase 1 neg:     2N          (two representative isolation probes per user)
  Phase 2 neg:     2k(N-1)     where k = number of users escalated
  ---
  Best case:       6N
  Worst case:      4N + 2N + 2N(N-1)
  Typical case:    4N + 2N + 2k(N-1)   where k << N

IMPORTANT — probes are generated from user_subnet_map (DB ground truth), NOT
from the ACL. A buggy ACL cannot influence which probes are generated or what
they expect to see.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Probe:
    src_user: str
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    expected: bool
    phase: int = 0                    # 0=positive, 1=phase1 sweep, 2=phase2 localisation
    dst_user: Optional[str] = None    # headscale_username of the destination tenant
                                      # required by real_executor.py for peer-visibility lookup
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
        print(f"Positive probes (4N):      {len(self.positive_probes)}")
        print(f"Phase 1 probes (2N):        {len(self.phase1_probes)}")
        print(f"Phase 2 probes 2k(N-1):     {len(self.phase2_probes)}")
        print(f"Total (this run):          {our_worst_case}")
        print(f"Naive exhaustive (H²×N(N-1)): {naive_exhaustive:,}")
        print(f"Reduction factor:          {naive_exhaustive / max(our_worst_case, 1):,.0f}x")
        print()
        print(f"Best case  (k=0): {len(self.positive_probes) + len(self.phase1_probes)} probes (6N)")
        print(f"Worst case (k=N): {len(self.positive_probes) + len(self.phase1_probes) + 2 * n_users * (n_users - 1)} probes (2N + 2N(N-1))")


class TwoPhaseProbeGenerator:
    HOST_OFFSETS = [10,200]

    def __init__(self, user_subnet_map: dict):
        """
        Args:
            user_subnet_map: headscale_username → subnet_cidr, from DB ground truth.
                             Built via DatabaseInterface.get_user_subnet_map().
                             Deliberately not derived from the ACL — a buggy ACL
                             must not influence which probes are generated.
        """
        self.user_subnet_map = user_subnet_map

    def _representative_ips(self, subnet_cidr: str) -> list[str]:
        """Return representative host IPs (.10 and .200) for a subnet."""
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        return [str(network.network_address + offset) for offset in self.HOST_OFFSETS]

    def _src_ip_for_user(self, username: str) -> str:
        subnet = self.user_subnet_map.get(username)
        return self._representative_ips(subnet)[0] if subnet else "0.0.0.0"

    def _get_user_subnets(self) -> list:
        """
        Returns list of (username, subnet) pairs from user_subnet_map.

        Reads from DB ground truth only — never from the ACL. Guarantees
        exactly N entries, one per user, giving true O(N) Phase 1.
        """
        return list(self.user_subnet_map.items())

    def generate_positive_probes(self) -> list:
        """4N positive probes — one ICMP + one TCP:22 per user for each representative dest IP"""
        probes = []
        for username, subnet in self.user_subnet_map.items():
            src_ip = self._src_ip_for_user(username)

            for dst_ip in self._representative_ips(subnet):
                probes.append(Probe(
                    src_user=username, src_ip=src_ip, dst_ip=dst_ip,
                    dst_port=0, proto="icmp", expected=True, phase=0,
                    dst_user=username,
                    description=f"{username} -> own subnet {subnet} (should allow)"
                ))
                probes.append(Probe(
                    src_user=username, src_ip=src_ip, dst_ip=dst_ip,
                    dst_port=22, proto="tcp", expected=True, phase=0,
                    dst_user=username,
                    description=f"{username} -> own subnet {subnet}:22 (should allow)"
                ))
        return probes

    def generate_phase1_probes(self) -> list:
        """2N Phase 1 probes — one user probes another tenant's .10 and .200 representatives.

        Returns empty list if N < 2 — Phase 1 requires at least 2 tenants.
        """
        user_subnets = self._get_user_subnets()

        if len(user_subnets) < 2:
            return []

        probes = []
        for i, (username, own_subnet) in enumerate(user_subnets):
            other_idx = (i + 1) % len(user_subnets)
            other_user, other_subnet = user_subnets[other_idx]

            src_ip = self._src_ip_for_user(username)
            
            for dst_ip in self._representative_ips(other_subnet):
                probes.append(Probe(
                    src_user=username, src_ip=src_ip, dst_ip=dst_ip,
                    dst_port=0, proto="icmp", expected=False, phase=1,
                    dst_user=other_user,
                    description=f"{username} -> {other_subnet} (isolation sweep, should deny)"
                ))

        return probes

    def generate_phase2_probes(self, users_with_leaks: list) -> list:
        """Phase 2 — 2k(N-1) targeted probes using .10 and .200 representatives.

        Only generated for users who failed Phase 1 or were flagged by the
        static checker. Tests ALL other subnets to localise exactly which
        boundary is violated.
        """
        probes = []
        user_subnets = self._get_user_subnets()

        for leaking_user in users_with_leaks:
            src_ip = self._src_ip_for_user(leaking_user)

            for other_user, other_subnet in user_subnets:
                if other_user == leaking_user:
                    continue
                for dst_ip in self._representative_ips(other_subnet):
                    probes.append(Probe(
                        src_user=leaking_user, src_ip=src_ip, dst_ip=dst_ip,
                        dst_port=0, proto="icmp", expected=False, phase=2,
                        dst_user=other_user,
                        description=f"{leaking_user} -> {other_subnet} (localisation, should deny)"
                    ))

        return probes

    def generate(self, users_with_leaks: Optional[list] = None) -> TwoPhaseProbeSet:
        """Generate the full two-phase probe set.

        If users_with_leaks is None, Phase 2 is not pre-generated.
        In real execution Phase 2 is generated after Phase 1 results are known.
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
    user_subnet_map = db.get_user_subnet_map()
    gen = TwoPhaseProbeGenerator(user_subnet_map)

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