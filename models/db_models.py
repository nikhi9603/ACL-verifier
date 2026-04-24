"""
Data models representing database entities used in the ACL verification system.
Includes users, subnet allocations, and lab deployments.
"""


from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

class UserRole(str, Enum):
    STUDENT    = "student"
    INSTRUCTOR = "instructor"
    ADMIN      = "admin"

class DeploymentStatus(str, Enum):
    QUEUED       = "queued"
    PROVISIONING = "provisioning"
    RUNNING      = "running"
    FAILED       = "failed"
    TERMINATING  = "terminating"
    EXPIRED      = "expired"


@dataclass
class User:
    id: str
    email: str
    name: str
    role: UserRole  # student, instructor, admin
    is_active: bool = True
    headscale_username: str = ""

    def __post_init__(self):
        if not self.headscale_username:
            self.headscale_username = self.email.split("@")[0].replace(".", "-")


@dataclass
class SubnetAllocation:
    user_id: str
    subnet_cidr: str  # e.g. 10.20.1.0/24


@dataclass
class LabDeployment:
    id: str
    user_id: str
    content_id: str
    status: DeploymentStatus  # queued, provisioning, running, failed, terminating, expired
    instance_private_ip: Optional[str] = None
