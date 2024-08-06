import logging
from typing import TYPE_CHECKING, Generator, Iterable

from Crypto.PublicKey import ECC

from secretstore.crypto import EncryptionPack
from secretstore.exceptions import SSHKeyNotFound
from secretstore.identity.dao import IdentityDAO
from secretstore.identity.entity import PrivateIdentity, PublicIdentity, RawIdentity

if TYPE_CHECKING:
    from secretstore.agent import SSHAgent
    from paramiko.agent import AgentKey

from sqlite3 import Connection


class IdentityManager:
    """Identity Manager. Handles all identity related actions"""

    def __init__(self, connection: "Connection", ssh_agent: "SSHAgent"):
        """
        Initialize the Manager.

        :param connection: The sqlite connection to use
        """

        self._dao = IdentityDAO(connection)
        self._ssh_agent = ssh_agent

    def get_identities(self) -> Iterable[PublicIdentity]:
        """Return all public identities found in the database"""
        return map(
            lambda ri: create_public_identity_from_raw(ri), self._dao.get_identities()
        )

    def _get_supported_keys(self) -> Iterable["AgentKey"]:
        """
        Return only the supported ssh keys found in the ssh agent.
        Currently two keys are supported: ED25519 and RSA.
        ECDSA is not supported because of its probabilitic signature
        """
        return filter(
            lambda key: key.algorithm_name in ["ED25519", "RSA"],
            self._ssh_agent.get_keys(),
        )

    def get_identities_based_ssh_agent(self) -> Iterable[PublicIdentity]:
        """Retrieve all public identities found in the database that are linked to the keys found in the ssh agent"""
        fingerprints = [key.fingerprint for key in self._get_supported_keys()]
        return map(
            lambda ri: create_public_identity_from_raw(ri),
            self._dao.get_identities_by_fingerprints(fingerprints),
        )

    def get_privates_identities(self) -> Generator[PrivateIdentity, None, None]:
        """
        Return all the private identity found.
        Because the identities are private and therefore private key unencrypted, only those linked to ssh key in the agent are returned.
        It is not possible to decrypt private keys that is not owned.
        """
        keys = {key.fingerprint: key for key in self._get_supported_keys()}
        for raw_id in self._dao.get_identities_by_fingerprints(list(keys.keys())):
            yield create_private_key_from_raw(raw_id, keys[raw_id.fingerprint])

    def create_identities(self) -> list[str]:
        """
        Create an identity for each supported key found in the ssh agent.
        If an identity already exists, do nothing for that key

        :return: The list of created identities fingerprints. The fingerprint is the ssh key one.
        """
        keys = list(self._get_supported_keys())
        if len(keys) == 0:
            raise SSHKeyNotFound()

        fingerprints = []
        for key in keys:
            exists = self._dao.get_keys_by_fingerprint(key.fingerprint) is not None
            if exists:
                logging.debug(
                    f"The identity for the key {key.fingerprint} already exists"
                )
                continue

            private_key = ECC.generate(curve="p256")
            public_key = private_key.public_key()
            identity = PrivateIdentity(key.fingerprint, public_key, private_key, key)

            self._dao.save_identity(identity)
            logging.debug(f"Created identity for the key {key.fingerprint}")
            fingerprints.append(identity.fingerprint)
        return fingerprints


def create_public_identity_from_raw(raw_identity: RawIdentity) -> "PublicIdentity":
    """
    Create a public identity from a raw one.

    :param raw_identity: The raw identity
    :return: The public identity
    """
    return PublicIdentity(
        raw_identity.fingerprint,
        ECC.import_key(raw_identity.public_key),
    )


def create_private_key_from_raw(
    raw_identity: RawIdentity, agent_key: "AgentKey"
) -> "PrivateIdentity":
    """
    Create a private identity from a raw one.

    :param raw_identity: The raw identity
    :para agent_key: The linked ssh key to decrypt the encrypted private key
    :return: The private identity
    """
    seed = raw_identity.private_key[: EncryptionPack.SEED_SIZE]
    private_key = raw_identity.private_key[EncryptionPack.SEED_SIZE :]

    epack = EncryptionPack.from_seed(agent_key, seed)
    return PrivateIdentity(
        raw_identity.fingerprint,
        ECC.import_key(raw_identity.public_key),
        ECC.import_key(private_key, passphrase=epack.encryption_key),
        agent_key,
    )
