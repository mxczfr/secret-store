from typing import TYPE_CHECKING

from paramiko.agent import Agent

from secretstore.exceptions import SSHKeyNotFound
from secretstore.utils import Singleton

if TYPE_CHECKING:
    from paramiko.agent import AgentKey


class SSHAgent(metaclass=Singleton):
    """
    High level class to handle the Paramiko SSH agent
    """

    def __init__(self):
        """Initialize the SSH agent"""
        self.agent = Agent()

    def get_keys(self) -> tuple["AgentKey", ...]:
        """Return all the keys stored by the ssh agent"""
        keys = self.agent.get_keys()

        if len(keys) == 0:
            raise SSHKeyNotFound()

        return keys
