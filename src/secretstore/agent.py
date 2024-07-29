from typing import TYPE_CHECKING

from paramiko.agent import Agent

from secretstore.exceptions import SSHKeyNotFound

if TYPE_CHECKING:
    from paramiko.agent import AgentKey


class SSHAgent:
    instance = None

    def __init__(self):
        self.agent = Agent()

    def get_keys(self) -> tuple["AgentKey", ...]:
        keys = self.agent.get_keys()

        if len(keys) == 0:
            raise SSHKeyNotFound()

        return keys

    @staticmethod
    def init() -> "SSHAgent":
        if SSHAgent.instance is None:
            SSHAgent.instance = SSHAgent()
        return SSHAgent.instance
