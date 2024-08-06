import json
from typing import TYPE_CHECKING

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from secretstore.agent import SSHAgent
from secretstore.exceptions import NoIdentityForStoreFound
from secretstore.guardian import GuardianManager
from secretstore.identity import IdentityManager
from secretstore.store import EncryptedStore, Store, StoreDAO

if TYPE_CHECKING:
    from sqlite3 import Connection


class SecretStoreManager:
    """
    SecretStore Manager. Big Manager object to handle and abstract all store / encryption / storage actions.
    """

    def __init__(self, connection: "Connection", ssh_agent: "SSHAgent"):
        """
        Initialize the Manager.

        :param connection: The sqlite connection to use
        :param ssh_agent: The ssh agent for ssh key manipulation
        """

        self._connection = connection
        self._ssh_agent = ssh_agent

        self.identity_manager = IdentityManager(self._connection)
        self._store_dao = StoreDAO(self._connection)
        self.guardian_manager = GuardianManager(self._connection)

    def new_store(self, store: Store):
        """
        Encrypt and save a new store in the database

        :param store: The store to save
        """
        # Encrypt the store data
        key = get_random_bytes(32)
        encrypted_store = encrypt_store(store, key)

        # Store the key for each identity
        ids = self.identity_manager.get_privates_identities(self._ssh_agent)
        for identity in ids:
            self.guardian_manager.create_guardian(store.name, identity, key)

        self._store_dao.save(encrypted_store)

    def get_store(self, name: str) -> Store | None:
        """Retrieve and decrypt a store in the database. Return None if nothing was found"""
        enc_store = self._store_dao.find(name)
        if enc_store is None:
            return None

        for private_identity in self.identity_manager.get_privates_identities(
            self._ssh_agent
        ):
            key = self.guardian_manager.get_store_encryption_key(name, private_identity)
            if key is not None:
                # decrypt store
                cipher = ChaCha20.new(key=key, nonce=enc_store.nonce)
                plaintext = cipher.decrypt(enc_store.ciphertext)
                data = json.loads(plaintext)
                return Store(name, data)

        raise NoIdentityForStoreFound(name)

    def update_store(self, store: Store):
        """
        Update an existing store. To update it, the user must have atleast one identity linked the the store

        :param store: The store to update
        """
        # Find an identiy that can encrypt the store
        key = None
        for private_identity in self.identity_manager.get_privates_identities(
            self._ssh_agent
        ):
            key = self.guardian_manager.get_store_encryption_key(
                store.name, private_identity
            )
            if key is not None:
                break
        if key is None:
            raise NoIdentityForStoreFound(store.name)

        self._store_dao.update(encrypt_store(store, key))

    def list_stores_name(self) -> list[str]:
        return self.guardian_manager.find_stores_names(
            list(self.identity_manager.get_privates_identities(self._ssh_agent))
        )


def encrypt_store(store: Store, key: bytes) -> EncryptedStore:
    """
    Encrypt store data with ChaCha20. A 8 bytes Nonce is generated each time.

    :param store: The store to encrypt
    :param key: The key to use for encryption. (32 bytes)
    :return: The Store with encrypted data
    """
    nonce = get_random_bytes(8)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = json.dumps(store.data).encode()
    ciphertext = cipher.encrypt(plaintext)
    return EncryptedStore(store.name, ciphertext, nonce)
