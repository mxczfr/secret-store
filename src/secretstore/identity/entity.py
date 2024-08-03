from dataclasses import dataclass
from typing import TYPE_CHECKING

from paramiko.agent import AgentKey

from secretstore.crypto import EncryptionPack

if TYPE_CHECKING:
    from Crypto.PublicKey.ECC import EccKey


@dataclass
class RawIdentity:
    """
    RawIdentity dataclass.
    Fields:
        - fingerprint: The ssh key fingerprint linked to the identity
        - public_key: the identity public key, in DER format
        - private_key: the identity private key, in DER format, protected by a passphrase
    """

    fingerprint: str
    public_key: bytes
    private_key: bytes


class PublicIdentity:
    """Public identity class"""

    def __init__(self, fingerprint: str, public_key: "EccKey"):
        """
        Initialize the Public identity

        :param fingerprint: The ssh key fingerprint linked to the identity
        :param public_key: The identity public key
        """
        self._fingerprint = fingerprint
        self._public_key = public_key

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def public_key(self) -> "EccKey":
        return self._public_key

    def get_bin_public_key(self) -> bytes:
        """Return the public key in DER format"""
        return self._public_key.export_key(format="DER")

    def __repr__(self) -> str:
        return f"{self._fingerprint} - {self.get_bin_public_key().hex()}"


class PrivateIdentity(PublicIdentity):
    """Private identity class, contains the private key unencrypted"""

    PROTECTION = "PBKDF2WithHMAC-SHA512AndAES128-CBC"

    def __init__(
        self,
        fingerprint: str,
        public_key: "EccKey",
        private_key: "EccKey",
        agent_key: "AgentKey",
    ):
        """
        Initialize the private identity

        :param fingerprint: The ssh key fingerprint linked to the identity
        :param public_key: The identity public key
        :param private_key: The unencrypted private key
        :param agent_key: The paramiko agent key linked to this identity
        """
        super().__init__(fingerprint, public_key)
        self._private_key = private_key
        self._agent_key = agent_key

    def get_bin_enc_priv_key(self) -> bytes:
        """Return the private key, encrypted and in DER format"""
        epack = EncryptionPack.new(self._agent_key)
        return epack.seed + self._private_key.export_key(
            format="DER",
            passphrase=epack.encryption_key,
            protection=PrivateIdentity.PROTECTION,
        )

    @property
    def private_key(self) -> "EccKey":
        return self._private_key
