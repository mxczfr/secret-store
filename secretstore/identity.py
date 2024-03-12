from typing import TYPE_CHECKING
from Crypto.PublicKey import ECC
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from secretstore.dao.identity import IdentityDAO

if TYPE_CHECKING:
    from sqlite3 import Connection
    from paramiko.agent import Agent, AgentKey
    from Crypto.PublicKey.ECC import EccKey


class Identity:

    def __init__(self, ssh_key: "AgentKey", agent: "Agent", public_key: "EccKey", private_key: "EccKey"):
        self.ssh_key: "AgentKey" = ssh_key
        self._agent: "Agent" = agent
        self._public_key: "EccKey" = public_key
        self._private_key: "EccKey" = private_key

    def _aes_key(self) -> bytes:
        signed_fingerprint = self.ssh_key.sign_ssh_data(self.ssh_key.fingerprint.encode())
        salt = get_random_bytes(16)
        

    def get_bin_public_key(self) -> bytes:
        return self._public_key.export_key(format="raw")

    def get_bin_enc_priv_key(self) -> bytes:

        
        

def get_or_create_identity(ssh_key: "AgentKey", agent: "Agent", connection: "Connection") -> Identity:

    private_key = ECC.generate(curve="ed25519")
    public_key = private_key.public_key()

    identity = Identity(ssh_key, agent, public_key, private_key)
    save_identity(identity, connection)
    return identity


def save_identity(identity: Identity, connection: "Connection"):
    identity_dao = IdentityDAO(connection)
    identity_dao.save_identity(identity)
