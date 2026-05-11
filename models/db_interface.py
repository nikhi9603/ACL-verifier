"""
Abstract interface for accessing cyberrange database state.
"""

from abc import ABC, abstractmethod
from typing import Optional, List
from models.db_models import User, SubnetAllocation, LabDeployment


class DatabaseInterface(ABC):

    @abstractmethod
    def get_active_users(self) -> List[User]:
        """
        Return all users who are active AND have a subnet allocation.
        """
        pass

    @abstractmethod
    def get_subnet_for_user(self, user_id: str) -> Optional[SubnetAllocation]:
        """
        Return the subnet allocation for a user, or None if not assigned.
        """
        pass

    @abstractmethod
    def get_running_labs_for_user(self, user_id: str) -> List[LabDeployment]:
        """
        Return all lab deployments for a user that are currently running.
        """
        pass

    def get_user_subnet_map(self) -> dict:
        """
        Return a mapping of headscale_username → subnet_cidr for all active
        users who have a subnet allocation.

        Concrete implementation derived from the two abstract methods above —
        subclasses get this for free without needing to reimplement it.
        Was previously duplicated in real_executor.py, scaling_evaluation.py,
        and two_phase_pipeline.py; centralised here by Nikitha (PR #4).
        """
        user_subnet_map = {}
        for user in self.get_active_users():
            subnet = self.get_subnet_for_user(user.id)
            if subnet:
                user_subnet_map[user.headscale_username] = subnet.subnet_cidr
        return user_subnet_map