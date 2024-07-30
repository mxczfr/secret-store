from typing import TYPE_CHECKING

from secretstore.agent import SSHAgent
from secretstore.identity.manager import IdentityManager
from secretstore.store.entity import Store
from secretstore.store.manager import StoreManager
from secretstore.store_key.manager import StoreKeyManager

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
        ids = self.identity_manager.get_privates_identities(self._ssh_agent)
        for identity in ids:
            encrypted_store = self.store_key_manager.encrypt_store(store, identity)
        self.store_manager.save(encrypted_store)
