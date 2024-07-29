import os
from typing import TYPE_CHECKING, Iterable

from Crypto.PublicKey import ECC
from secretstore.crypto import EncryptionPack
from secretstore.identity.entity import (
    PrivateIdentity,
    PublicIdentity,
    create_public_identity_from_raw,
)

if TYPE_CHECKING:
    from secretstore.agent import SSHAgent
    from secretstore.dao import IdentityDAO


class IdentityManager:
    def __init__(self, dao: "IdentityDAO"):
        self._dao = dao

    def get_identities(self) -> Iterable[PublicIdentity]:
        return map(
            lambda ri: create_public_identity_from_raw(ri), self._dao.get_identities()
        )

    def get_identities_based_ssh_agent(
        self, ssh_agent: "SSHAgent"
    ) -> Iterable[PublicIdentity]:
        fingerprints = [key.fingerprint for key in ssh_agent.get_keys()]
        return map(
            lambda ri: create_public_identity_from_raw(ri),
            self._dao.get_identities_by_fingerprints(fingerprints),
        )

    def create_identities(self, ssh_agent: "SSHAgent"):
        for key in ssh_agent.get_keys():
            exists = self._dao.get_keys_by_fingerprint(key.fingerprint) is not None
            if exists:
                print(f"The identity for the key {key.fingerprint} already exists")
                continue

            private_key = ECC.generate(curve="ed25519")
            public_key = private_key.public_key()
            seed = os.urandom(EncryptionPack.SEED_SIZE)
            identity = PrivateIdentity(
                key.fingerprint, public_key, private_key, key, seed
            )

            self._dao.save_identity(identity)
            print(f"Created identity for the key {key.fingerprint}")
