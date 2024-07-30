from typing import TYPE_CHECKING, Generator

from secretstore.identity.entity import RawIdentity
from secretstore.utils import Singleton

if TYPE_CHECKING:
    from sqlite3 import Connection

    from secretstore.identity.entity import PrivateIdentity

_TABLE = """create table if not exists
identities(
    fingerprint text primary key,
    public_key blob,
    private_key blob
)"""


class IdentityDAO(metaclass=Singleton):
    def __init__(self, connection: "Connection"):
        self._connection = connection
        cur = self._connection.cursor()
        cur.execute(_TABLE)
        cur.close()

    def get_identities(self) -> Generator[RawIdentity, None, None]:
        res = self._connection.execute("select * from identities")
        for i in res.fetchall():
            yield RawIdentity(*i)

    def get_identities_by_fingerprints(
        self, fingerprints: list[str]
    ) -> Generator[RawIdentity, None, None]:
        q = f"select * from identities where fingerprint in ({','.join(['?']*len(fingerprints))})"
        res = self._connection.execute(q, fingerprints)
        for i in res.fetchall():
            yield RawIdentity(*i)

    def get_keys_by_fingerprint(self, fingerprint: str) -> tuple[bytes, bytes] | None:
        res = self._connection.execute(
            "select public_key, private_key from identities where fingerprint=?",
            [fingerprint],
        )
        return res.fetchone()

    def save_identity(self, identity: "PrivateIdentity"):
        with self._connection as conn:
            conn.execute(
                "insert into identities(fingerprint, public_key, private_key) values (?,?,?)",
                (
                    identity._fingerprint,
                    identity.get_bin_public_key(),
                    identity.get_bin_enc_priv_key(),
                ),
            )
