from typing import TYPE_CHECKING

from secretstore.utils import Singleton

from secretstore.store_key.entity import StoreKey

if TYPE_CHECKING:
    from sqlite3 import Connection

_TABLE = """create table if not exists
store_key(
    store_name text,
    identity_fingerprint text,
    aead blob,
    key blob,
    primary key (store_name, identity_fingerprint)
)"""


class StoreKeyDAO(metaclass=Singleton):
    def __init__(self, connection: "Connection"):
        self._connection = connection
        self._connection.execute(_TABLE)


    def find(self, store_name: str, identity_fingerprint: str) -> StoreKey | None:
        cur = self._connection.execute(
            "select * from store_key where store_name=? and identity_fingerprint=?",
            (store_name, identity_fingerprint)
        )
        result = cur.fetchone()
        if result is None:
            return None
        return StoreKey(*result)

    def save(self, store_key: StoreKey):
        with self._connection as conn:
            conn.execute("insert into store_key values (?,?,?,?)",
                         (store_key.store_name, store_key.identity_fingerprint, store_key.aead_enc, store_key.key_enc)
                         )


