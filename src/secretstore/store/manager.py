from typing import TYPE_CHECKING
from secretstore.store.dao import StoreDAO
from secretstore.store.entity import EncryptedStore

if TYPE_CHECKING:
    from sqlite3 import Connection

class StoreManager:
    def __init__(self, connection: "Connection"):
        self._dao = StoreDAO(connection)

    def save(self, encrypted_store: EncryptedStore):
        self._dao.save(encrypted_store)

    def find(self, name: str) -> EncryptedStore | None:
        return self._dao.find(name)
