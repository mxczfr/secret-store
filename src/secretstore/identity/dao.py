from typing import TYPE_CHECKING, Generator

from secretstore.identity.entity import RawIdentity
from secretstore.utils import Singleton

if TYPE_CHECKING:
    from sqlite3 import Connection

    from secretstore.identity.entity import PrivateIdentity

_TABLE_NAME = "identities"
_TABLE = f"""create table if not exists
 {_TABLE_NAME}(
    fingerprint text primary key,
    public_key blob,
    private_key blob
)"""


class IdentityDAO(metaclass=Singleton):
    """Data Access Object for Identity Object."""

    def __init__(self, connection: "Connection"):
        """
        Initialize the DAO and create the table if it doesn't exist

        :param connection: The sqlite connection to use
        """
        self._connection = connection
        cur = self._connection.cursor()
        cur.execute(_TABLE)
        cur.close()

    def get_identities(self) -> Generator[RawIdentity, None, None]:
        """
        Retrieve all identities in the database

        :return: identities or an empty generator if no identity in the database
        """
        res = self._connection.execute(f"select * from {_TABLE_NAME}")
        for i in res.fetchall():
            yield RawIdentity(*i)

    def get_identities_by_fingerprints(
        self, fingerprints: list[str]
    ) -> Generator[RawIdentity, None, None]:
        """
        Retrieve all identities linked to fingerprints

        :param fingerprints: All the fingerprints to filter identities
        :return: identities linked to the fingerprints or an empty generator if nothing was found
        """
        q = f"select * from {_TABLE_NAME} where fingerprint in ({','.join(['?']*len(fingerprints))})"
        res = self._connection.execute(q, fingerprints)
        for i in res.fetchall():
            yield RawIdentity(*i)

    def get_keys_by_fingerprint(self, fingerprint: str) -> tuple[bytes, bytes] | None:
        """
        Retrieve the public and private key of an identity based on its fingerprint.

        :return: A tuple (public, private) keys or None if nothing was found
        """        
        res = self._connection.execute(
            f"select public_key, private_key from {_TABLE_NAME} where fingerprint=?",
            [fingerprint],
        )
        return res.fetchone()

    def save_identity(self, identity: "PrivateIdentity"):
        """
        Save a new private Identity into the database. 
        Only private identities are saved because the public one is forgeable with the private
        
        :param identity: The private identity to save
        """
        with self._connection as conn:
            conn.execute(
                f"insert into {_TABLE_NAME}(fingerprint, public_key, private_key) values (?,?,?)",
                (
                    identity._fingerprint,
                    identity.get_bin_public_key(),
                    identity.get_bin_enc_priv_key(),
                ),
            )
