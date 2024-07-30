import json
from typing import TYPE_CHECKING

from secretstore.agent import SSHAgent
from secretstore.identity.manager import IdentityManager
from secretstore.store.entity import EncryptedStore, Store
from secretstore.store.manager import StoreManager
from secretstore.store_key.manager import StoreKeyManager
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes


if TYPE_CHECKING:
    from sqlite3 import Connection


class SecretStoreManager:
    def __init__(self, connection: "Connection", ssh_agent: "SSHAgent"):
        self._connection = connection
        self._ssh_agent = ssh_agent

        self.identity_manager = IdentityManager(self._connection)
        self.store_manager = StoreManager(self._connection)
        self.store_key_manager = StoreKeyManager(self._connection)


    def new_store(self, store: "Store"):
        # Encrypt the store data
        key = get_random_bytes(32)
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        
        plaintext = json.dumps(store.data).encode()
        ciphertext = cipher.encrypt(plaintext)

        # Store the key for each identity
        ids = self.identity_manager.get_privates_identities(self._ssh_agent)
        for identity in ids:
            encrypted_store = self.store_key_manager.create_store_key(store, identity, key)

        encrypted_store = EncryptedStore(store.name, ciphertext, nonce)
        self.store_manager.save(encrypted_store)
