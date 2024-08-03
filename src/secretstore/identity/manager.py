from typing import TYPE_CHECKING, Generator, Iterable

from Crypto.PublicKey import ECC

from secretstore.exceptions import SSHKeyNotFound
from secretstore.identity.dao import IdentityDAO
from secretstore.identity.entity import PrivateIdentity, PublicIdentity, RawIdentity
from secretstore.crypto import EncryptionPack

if TYPE_CHECKING:
    from secretstore.agent import SSHAgent
    from paramiko.agent import AgentKey

from sqlite3 import Connection


class IdentityManager:
    def __init__(self, connection: "Connection"):
        self._dao = IdentityDAO(connection)

    def get_identities(self) -> Iterable[PublicIdentity]:
        return map(
            lambda ri: create_public_identity_from_raw(ri), self._dao.get_identities()
        )

    def _get_supported_keys(self, ssh_agent: "SSHAgent") -> Iterable["AgentKey"]:
        return filter(
            lambda key: key.algorithm_name in ["ED25519", "RSA"], ssh_agent.get_keys()
        )

    def get_identities_based_ssh_agent(
        self, ssh_agent: "SSHAgent"
    ) -> Iterable[PublicIdentity]:
        fingerprints = [key.fingerprint for key in self._get_supported_keys(ssh_agent)]
        return map(
            lambda ri: create_public_identity_from_raw(ri),
            self._dao.get_identities_by_fingerprints(fingerprints),
        )

    def get_privates_identities(
        self, ssh_agent: "SSHAgent"
    ) -> Generator[PrivateIdentity, None, None]:
        keys = {key.fingerprint: key for key in self._get_supported_keys(ssh_agent)}
        for raw_id in self._dao.get_identities_by_fingerprints(list(keys.keys())):
            yield create_private_key_from_raw(raw_id, keys[raw_id.fingerprint])

    def create_identities(self, ssh_agent: "SSHAgent"):
        keys = list(self._get_supported_keys(ssh_agent))
        if len(keys) == 0:
            raise SSHKeyNotFound()
        for key in keys:
            exists = self._dao.get_keys_by_fingerprint(key.fingerprint) is not None
            if exists:
                print(f"The identity for the key {key.fingerprint} already exists")
                continue

            private_key = ECC.generate(curve="p256")
            public_key = private_key.public_key()
            identity = PrivateIdentity(key.fingerprint, public_key, private_key, key)

            self._dao.save_identity(identity)
            print(f"Created identity for the key {key.fingerprint}")


def create_public_identity_from_raw(raw_identity: RawIdentity) -> "PublicIdentity":
    return PublicIdentity(
        raw_identity.fingerprint,
        ECC.import_key(raw_identity.public_key),
    )


def create_private_key_from_raw(
    raw_identity: RawIdentity, agent_key: "AgentKey"
) -> "PrivateIdentity":
    seed = raw_identity.private_key[: EncryptionPack.SEED_SIZE]
    private_key = raw_identity.private_key[EncryptionPack.SEED_SIZE :]

    epack = EncryptionPack.from_seed(agent_key, seed)
    return PrivateIdentity(
        raw_identity.fingerprint,
        ECC.import_key(raw_identity.public_key),
        ECC.import_key(private_key, passphrase=epack.encryption_key),
        agent_key,
    )
