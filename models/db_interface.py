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
    def get_subnet_for_user(self, user_id:str) -> Optional[SubnetAllocation]:
        """
        Return the subnet allocation for a user, or None if not assigned.
        """
        pass

    @abstractmethod
    def get_running_labs_for_user(self, user_id:str) -> List[LabDeployment]:
        """
        Return all lab deployments for a user that are currently running.
        """
        pass
