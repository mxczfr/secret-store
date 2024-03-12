from typing import TYPE_CHECKING

from secretstore.utils import Singleton

if TYPE_CHECKING:
    from sqlite3 import Connection
    from secretstore.identity import Identity

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

    def get_keys_by_fingerprint(self, fingerprint: str) -> tuple[bytes, bytes]:
        res = self._connection.execute(
            "select public_key, private_key from identities where fingerprint=?",
            fingerprint)

        print(res.fetchone())

    def save_identity(self, identity: "Identity"):
        cur = self._connection.cursor()
        cur.execute("insert into identities(public_key, private_key) values (?,?)",
                    (identity.get_bin_public_key(), identity.get_bin_enc_priv_key()))
        cur.commit()
        cur.close()
