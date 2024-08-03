from typing import TYPE_CHECKING

from secretstore.store.entity import EncryptedStore
from secretstore.utils import Singleton

if TYPE_CHECKING:
    from sqlite3 import Connection

_TABLE = """create table if not exists
store(
    name text primary key,
    ciphertext blob,
    nonce blob
)"""


class StoreDAO(metaclass=Singleton):
    def __init__(self, connection: "Connection"):
        self._connection = connection
        self._connection.execute(_TABLE)

    def save(self, encrypted_store: EncryptedStore):
        with self._connection as conn:
            conn.execute(
                "insert into store values(?,?,?)",
                (
                    encrypted_store.name,
                    encrypted_store.ciphertext,
                    encrypted_store.nonce,
                ),
            )

    def find(self, name: str) -> EncryptedStore | None:
        cur = self._connection.execute("select * from store where name=?", [name])
        result = cur.fetchone()
        if result:
            return EncryptedStore(*result)
        return None
