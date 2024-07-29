from typing import TYPE_CHECKING
from dataclasses import dataclass
from Crypto.PublicKey import ECC
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
    def fingerprint(self):
        return self._fingerprint

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
        seed: bytes,
    ):
        super().__init__(fingerprint, public_key)
        self._private_key = private_key
        self._agent_key = agent_key
        self._seed = seed

    def get_bin_enc_priv_key(self) -> bytes:
        passphrase = EncryptionPack.from_seed(
            self._agent_key, self._seed
        ).encryption_key
        return self._private_key.export_key(
            format="DER", passphrase=passphrase, protection=PrivateIdentity.PROTECTION
        )


def create_public_identity_from_raw(raw_identity: RawIdentity) -> "PublicIdentity":
    return PublicIdentity(
        raw_identity.fingerprint,
        ECC.import_key(raw_identity.public_key),
    )


def create_private_key_from_raw(
    raw_identity: RawIdentity, agent_key: "AgentKey"
) -> "PrivateIdentity":
    private_key = raw_identity.private_key[: -EncryptionPack.SEED_SIZE]
    seed = private_key[-EncryptionPack.SEED_SIZE :]

    epack = EncryptionPack.from_seed(agent_key, seed)

    return PrivateIdentity(
        raw_identity.fingerprint,
        ECC.import_key(raw_identity.public_key),
        ECC.import_key(raw_identity.private_key),
        agent_key,
        seed,
    )
