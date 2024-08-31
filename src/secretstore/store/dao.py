from typing import TYPE_CHECKING

from secretstore.store.entity import EncryptedStore
from secretstore.utils import Singleton

if TYPE_CHECKING:
    from sqlite3 import Connection
    from secretstore.store.entity import Store

_TABLE_NAME = "store"
_TABLE = f"""create table if not exists
 {_TABLE_NAME}(
    name text primary key,
    ciphertext blob,
    nonce blob
)"""


class StoreDAO(metaclass=Singleton):
    """Data Access Object for Store Object."""

    def __init__(self, connection: "Connection"):
        """
        Initialize the DAO and create the table if it doesn't exist

        :param connection: The sqlite connection to use
        """
        self._connection = connection
        self._connection.execute(_TABLE)

    def save(self, encrypted_store: EncryptedStore):
        """
        Save a new store.

        :param encrypted_store: The store to save with its data already encrypted
        """
        with self._connection as conn:
            conn.execute(
                f"insert into {_TABLE_NAME} values(?,?,?)",
                (
                    encrypted_store.name,
                    encrypted_store.ciphertext,
                    encrypted_store.nonce,
                ),
            )

    def find(self, name: str) -> EncryptedStore | None:
        """
        Find a store based on its name.

        :return: The encrypted store or None if nothing was found
        """
        cur = self._connection.execute("select * from store where name=?", [name])
        result = cur.fetchone()
        if result:
            return EncryptedStore(*result)
        return None

    def update(self, enc_store: EncryptedStore):
        """
        Update an existing store

        :param enc_store: The store to update
        """
        with self._connection as conn:
            conn.execute(
                f"update {_TABLE_NAME} set ciphertext=?, nonce=? where name=?",
                [enc_store.ciphertext, enc_store.nonce, enc_store.name],
            )

    def delete(self, store: "Store"):
        """
        Delete a store in the database.

        :param store: The store to delete
        """
        with self._connection as conn:
            conn.execute(f"delete from {_TABLE_NAME} where name=?", [store.name])
