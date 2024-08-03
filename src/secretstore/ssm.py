import json
from typing import TYPE_CHECKING

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from secretstore.agent import SSHAgent
from secretstore.exceptions import NoIdentityForStoreFound
from secretstore.identity.manager import IdentityManager
from secretstore.store.dao import StoreDAO
from secretstore.store.entity import EncryptedStore, Store
from secretstore.guardian import GuardianManager

if TYPE_CHECKING:
    from sqlite3 import Connection


class SecretStoreManager:
    def __init__(self, connection: "Connection", ssh_agent: "SSHAgent"):
        self._connection = connection
        self._ssh_agent = ssh_agent

        self.identity_manager = IdentityManager(self._connection)
        self._store_dao = StoreDAO(self._connection)
        self.guardian_manager = GuardianManager(self._connection)


    def new_store(self, store: Store):
        # Encrypt the store data
        key = get_random_bytes(32)
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        
        plaintext = json.dumps(store.data).encode()
        ciphertext = cipher.encrypt(plaintext)

        # Store the key for each identity
        ids = self.identity_manager.get_privates_identities(self._ssh_agent)
        for identity in ids:
            encrypted_store = self.guardian_manager.create_store_key(store.name, identity, key)

        encrypted_store = EncryptedStore(store.name, ciphertext, nonce)
        self._store_dao.save(encrypted_store)

    def get_store(self, name: str) -> Store|None:
        enc_store = self._store_dao.find(name)
        if enc_store is None:
            return None

        for private_identity in self.identity_manager.get_privates_identities(self._ssh_agent):
            key = self.guardian_manager.get_store_encryption_key(name, private_identity)
            if key is not None:
                # decrypt store
                cipher = ChaCha20.new(key=key, nonce=enc_store.nonce)
                plaintext = cipher.decrypt(enc_store.ciphertext)
                data = json.loads(plaintext)
                return Store(name, data)
        
        raise NoIdentityForStoreFound(name)
