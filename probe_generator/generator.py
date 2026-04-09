"""
Probe Generator — ATPG-inspired minimal probe set derivation.
Generates positive probes (should succeed) and negative probes (should fail).
"""

import ipaddress
from dataclasses import dataclass
from typing import Optional


@dataclass
class Probe:
    src_user: str
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    expected: bool
    rule_index: Optional[int] = None
    description: str = ""

    def __str__(self):
        verdict = "ALLOW" if self.expected else "DENY"
        return (f"[{verdict}] {self.src_user} {self.src_ip} -> "
                f"{self.dst_ip}:{self.dst_port}/{self.proto} ({self.description})")


class ProbeGenerator:
    HOST_OFFSET = 10

    def __init__(self, policy, user_subnet_map: dict):
        self.policy = policy
        self.user_subnet_map = user_subnet_map

    def _representative_ip(self, subnet_cidr: str) -> str:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        return str(network.network_address + self.HOST_OFFSET)

    def _src_ip_for_user(self, username: str) -> str:
        subnet = self.user_subnet_map.get(username)
        if subnet:
            return self._representative_ip(subnet)
        return "0.0.0.0"

    def _extract_username(self, src_entry: str) -> Optional[str]:
        if src_entry.endswith("@"):
            return src_entry[:-1]
        return None

    def _extract_subnet(self, dst_entry: str) -> Optional[str]:
        if ":" in dst_entry:
            return dst_entry.rsplit(":", 1)[0]
        return dst_entry

    def generate_positive_probes(self) -> list:
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
                    probes.append(Probe(src_user=username, src_ip=src_ip, dst_ip=dst_ip,
                                        dst_port=0, proto="icmp", expected=True, rule_index=i,
                                        description=f"rule {i}: {username} -> {subnet} (should allow)"))
                    probes.append(Probe(src_user=username, src_ip=src_ip, dst_ip=dst_ip,
                                        dst_port=22, proto="tcp", expected=True, rule_index=i,
                                        description=f"rule {i}: {username} -> {subnet}:22 (should allow)"))
        return probes

    def generate_negative_probes(self) -> list:
        probes = []
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

        seen_pairs = set()
        for user_a, subnet_a in user_subnets:
            for user_b, subnet_b in user_subnets:
                if user_a == user_b:
                    continue
                pair_key = (user_a, subnet_b)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                src_ip = self._src_ip_for_user(user_a)
                dst_ip = self._representative_ip(subnet_b)
                probes.append(Probe(src_user=user_a, src_ip=src_ip, dst_ip=dst_ip,
                                    dst_port=0, proto="icmp", expected=False,
                                    description=f"isolation: {user_a} -> {subnet_b} (should deny)"))
        return probes

    def generate(self) -> list:
        return self.generate_positive_probes() + self.generate_negative_probes()

    def summarize(self, probes: list) -> None:
        positive = [p for p in probes if p.expected]
        negative = [p for p in probes if not p.expected]
        n_users = len(self.user_subnet_map)
        naive_count = n_users * n_users
        print(f"Probe Set Summary")
        print(f"{'=' * 50}")
        print(f"Users/tenants:          {n_users}")
        print(f"Naive NxN probe count:  {naive_count}")
        print(f"Positive probes (2N):   {len(positive)}")
        print(f"Negative probes N(N-1): {len(negative)}")
        print(f"Total probes:           {len(probes)}")


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
    probe_gen = ProbeGenerator(policy, user_subnet_map)
    probes = probe_gen.generate()
    probe_gen.summarize(probes)