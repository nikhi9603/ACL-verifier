"""
ACL Generator for Headscale.
Reads user and subnet allocation data and generates a correct Headscale huJSON policy.
"""
from models.policy import ACLRule, HeadscalePolicy
from models.db_interface import DatabaseInterface
from synthetic_data.generator import generate_synthetic_db

class ACLGenerator:
    ROUTER_TAG = "tag:router"
    MANAGEMENT_SUBNET = "10.20.0.0/16"

    def __init__(self, db: DatabaseInterface):
        self.db = db

    def generate(self) -> HeadscalePolicy:
        acls = []
        active_users = self.db.get_active_users()
        admins = [u for u in active_users if u.role == "admin"]
        regular_users = [u for u in active_users if u.role != "admin"]

        if admins:
            acls.append(ACLRule(
                action="accept",
                src=[f"{u.headscale_username}@" for u in admins],
                dst=[f"{self.MANAGEMENT_SUBNET}:*"]
            ))

        for user in regular_users:
            subnet = self.db.get_subnet_for_user(user.id)
            if not subnet:
                continue
            acls.append(ACLRule(
                action="accept",
                src=[f"{user.headscale_username}@"],
                dst=[f"{subnet.subnet_cidr}:*"]
            ))

        return HeadscalePolicy(
            tag_owners={self.ROUTER_TAG: []},
            acls=acls,
            auto_approvers={"routes": {self.MANAGEMENT_SUBNET: [self.ROUTER_TAG]}}
        )

    def generate_and_write(self, output_path: str) -> HeadscalePolicy:
        policy = self.generate()
        with open(output_path, "w") as f:
            f.write(policy.to_hujson())
        print(f"Policy written to {output_path}")
        return policy


if __name__ == "__main__":
    from synthetic_data.generator import generate_synthetic_db
    db = generate_synthetic_db(num_students=5, num_instructors=1)
    generator = ACLGenerator(db)
    policy = generator.generate()
    print(policy.to_hujson())
    print(f"\nTotal ACL rules: {len(policy.acls)}")