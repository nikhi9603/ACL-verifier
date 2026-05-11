"""
Shared pytest fixtures for the CyberRange ACL Verifier test suite.

Pytest injects these automatically — never import conftest directly.
Shared helper functions live in tests/helpers.py instead.

All fixtures are pure Python — no network, no SSH, no Headscale, no Postgres.
"""

import pytest

from synthetic_data.generator import generate_synthetic_db, SyntheticDatabase
from acl_generator.generator import ACLGenerator
from models.policy import HeadscalePolicy, ACLRule
from models.db_models import User, SubnetAllocation, UserRole


# ── Canonical 3-student, 1-instructor DB ──────────────────────────────────────
# Subnets: instructor1 → 10.20.1.0/24
#          student1    → 10.20.2.0/24
#          student2    → 10.20.3.0/24
#          student3    → 10.20.4.0/24

@pytest.fixture
def db() -> SyntheticDatabase:
    return generate_synthetic_db(num_students=3, num_instructors=1)


@pytest.fixture
def policy(db) -> HeadscalePolicy:
    return ACLGenerator(db).generate()


@pytest.fixture
def clean_policy(db) -> HeadscalePolicy:
    """Alias — explicit name for tests that need to make the intent clear."""
    return ACLGenerator(db).generate()


@pytest.fixture
def user_subnet_map(db) -> dict:
    """headscale_username → subnet_cidr, built from DB ground truth."""
    result = {}
    for user in db.get_active_users():
        subnet = db.get_subnet_for_user(user.id)
        if subnet:
            result[user.headscale_username] = subnet.subnet_cidr
    return result