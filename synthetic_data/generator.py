"""
Synthetic data generator for cyberrange ACL verifier.
Mimics the real PostgreSQL schema without needing a live DB.
"""

import uuid
from dataclasses import dataclass, field
from typing import List, Optional
from models.db_models import User, SubnetAllocation, LabDeployment, DeploymentStatus, UserRole
from models.db_interface import DatabaseInterface

@dataclass
class SyntheticDatabase(DatabaseInterface):
    users: List[User] = field(default_factory=list)
    subnet_allocations: List[SubnetAllocation] = field(default_factory=list)
    lab_deployments: List[LabDeployment] = field(default_factory=list)

    def get_active_users(self):
        allocated_user_ids = {s.user_id for s in self.subnet_allocations}
        return [u for u in self.users if u.is_active and u.id in allocated_user_ids]

    def get_subnet_for_user(self, user_id: str) -> Optional[SubnetAllocation]:
        for s in self.subnet_allocations:
            if s.user_id == user_id:
                return s
        return None

    def get_running_labs_for_user(self, user_id: str) -> list:
        return [d for d in self.lab_deployments if d.user_id == user_id and d.status == DeploymentStatus.RUNNING]


def generate_synthetic_db(num_students: int = 5, num_instructors: int = 1) -> SyntheticDatabase:
    db = SyntheticDatabase()
    subnet_octet = 1

    for i in range(num_instructors):
        user_id = str(uuid.uuid4())
        user = User(id=user_id, email=f"instructor{i+1}@cyberrange.local",
                    name=f"Instructor {i+1}", role=UserRole.INSTRUCTOR)
        db.users.append(user)
        db.subnet_allocations.append(SubnetAllocation(user_id=user_id,
                                                       subnet_cidr=f"10.20.{subnet_octet}.0/24"))
        db.lab_deployments.append(LabDeployment(id=str(uuid.uuid4()), user_id=user_id,
                                                  content_id=str(uuid.uuid4()), status=DeploymentStatus.RUNNING,
                                                  instance_private_ip=f"10.20.{subnet_octet}.10"))
        subnet_octet += 1

    for i in range(num_students):
        user_id = str(uuid.uuid4())
        user = User(id=user_id, email=f"student{i+1}@cyberrange.local",
                    name=f"Student {i+1}", role=UserRole.STUDENT)
        db.users.append(user)
        db.subnet_allocations.append(SubnetAllocation(user_id=user_id,
                                                       subnet_cidr=f"10.20.{subnet_octet}.0/24"))
        if i % 2 == 0:
            db.lab_deployments.append(LabDeployment(id=str(uuid.uuid4()), user_id=user_id,
                                                      content_id=str(uuid.uuid4()), status=DeploymentStatus.RUNNING,
                                                      instance_private_ip=f"10.20.{subnet_octet}.10"))
        subnet_octet += 1

    return db


if __name__ == "__main__":
    db = generate_synthetic_db(num_students=5, num_instructors=1)
    print(f"Generated {len(db.users)} users, {len(db.subnet_allocations)} subnets")
    for user in db.users:
        subnet = db.get_subnet_for_user(user.id)
        print(f"  {user.name} ({user.role.value}) -> {subnet.subnet_cidr if subnet else 'none'}")