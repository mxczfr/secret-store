from typing import TYPE_CHECKING

from secretstore.guardian.entity import Guardian
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
    """Data Access Object for Guardian Object."""

    def __init__(self, connection: "Connection"):
        """
        Initialize the DAO and create the table if it doesn't exist

        :param connection: The sqlite connection to use
        """
        self._connection = connection
        self._connection.execute(_TABLE)

    def find(self, store_name: str, identity_fingerprint: str) -> Guardian | None:
        """
        Find a guardian in the database.

        :param store_name: The linked store name
        :param identity_fingerprint: The private identity fingerprint linked to the guardian
        :return: The Guardian or None if nothing was found
        """
        cur = self._connection.execute(
            f"select * from {_TABLE_NAME} where store_name=? and identity_fingerprint=?",
            (store_name, identity_fingerprint),
        )
        result = cur.fetchone()
        if result is None:
            return None
        return Guardian(*result)

    def save(self, guardian: Guardian):
        """
        Save a new guardian in the database

        :param guardian: the guardian to save
        """
        with self._connection as conn:
            conn.execute(
                f"insert into {_TABLE_NAME} values (?,?,?,?)",
                (
                    guardian.store_name,
                    guardian.identity_fingerprint,
                    guardian.aead_enc,
                    guardian.enc_key,
                ),
            )

    def find_stores_names(self, fingerprints: list[str]) -> list[str]:
        return [
            row[0]
            for row in self._connection.execute(
                f"select store_name from {_TABLE_NAME} where identity_fingerprint in ({','.join(['?']*len(fingerprints))}) group by store_name",
                fingerprints,
            ).fetchall()
        ]
