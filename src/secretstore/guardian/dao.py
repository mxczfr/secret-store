from typing import TYPE_CHECKING

from secretstore.guardian.entity import Guarian
from secretstore.utils import Singleton

if TYPE_CHECKING:
    from sqlite3 import Connection

_TABLE_NAME = "guardians"
_TABLE = f"""create table if not exists
 {_TABLE_NAME}(
    store_name text,
    identity_fingerprint text,
    aead blob,
    key blob,
    primary key (store_name, identity_fingerprint)
)"""


class GuardianDAO(metaclass=Singleton):
    def __init__(self, connection: "Connection"):
        self._connection = connection
        self._connection.execute(_TABLE)

    def find(self, store_name: str, identity_fingerprint: str) -> Guarian | None:
        cur = self._connection.execute(
            f"select * from {_TABLE_NAME} where store_name=? and identity_fingerprint=?",
            (store_name, identity_fingerprint),
        )
        result = cur.fetchone()
        if result is None:
            return None
        return Guarian(*result)

    def save(self, store_key: Guarian):
        with self._connection as conn:
            conn.execute(
                f"insert into {_TABLE_NAME} values (?,?,?,?)",
                (
                    store_key.store_name,
                    store_key.identity_fingerprint,
                    store_key.aead_enc,
                    store_key.key_enc,
                ),
            )
