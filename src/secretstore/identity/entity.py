from dataclasses import dataclass
from typing import TYPE_CHECKING

from paramiko.agent import AgentKey

from secretstore.crypto import EncryptionPack

if TYPE_CHECKING:
    from Crypto.PublicKey.ECC import EccKey


@dataclass
class RawIdentity:
    fingerprint: str
    public_key: bytes
    private_key: bytes


class PublicIdentity:
    def __init__(self, fingerprint: str, public_key: "EccKey"):
        self._fingerprint = fingerprint
        self._public_key = public_key

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def public_key(self) -> "EccKey":
        return self._public_key

    def get_bin_public_key(self) -> bytes:
        return self._public_key.export_key(format="DER")

    def __repr__(self) -> str:
        return f"{self._fingerprint} - {self.get_bin_public_key().hex()}"


class PrivateIdentity(PublicIdentity):
    PROTECTION = "PBKDF2WithHMAC-SHA512AndAES128-CBC"

    def __init__(
        self,
        fingerprint: str,
        public_key: "EccKey",
        private_key: "EccKey",
        agent_key: "AgentKey",
    ):
        super().__init__(fingerprint, public_key)
        self._private_key = private_key
        self._agent_key = agent_key

    def get_bin_enc_priv_key(self) -> bytes:
        epack = EncryptionPack.new(self._agent_key)
        return epack.seed + self._private_key.export_key(
            format="DER",
            passphrase=epack.encryption_key,
            protection=PrivateIdentity.PROTECTION,
        )

    @property
    def private_key(self) -> "EccKey":
        return self._private_key
