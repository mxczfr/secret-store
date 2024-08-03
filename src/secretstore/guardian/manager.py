from typing import TYPE_CHECKING

import pyhpke

from secretstore.guardian.dao import GuardianDAO
from secretstore.guardian.entity import Guarian
from secretstore.identity.entity import PrivateIdentity

if TYPE_CHECKING:
    from sqlite3 import Connection


class GuardianManager:
    def __init__(self, connection: "Connection"):
        self._dao = GuardianDAO(connection)

    def _get_hpke_cipher_suite(self) -> pyhpke.CipherSuite:
        return pyhpke.CipherSuite.new(
            pyhpke.KEMId.DHKEM_P256_HKDF_SHA256,
            pyhpke.KDFId.HKDF_SHA256,
            pyhpke.AEADId.AES256_GCM,
        )

    def create_store_key(
        self, store_name: str, private_identity: PrivateIdentity, key: bytes
    ):
        # Encrypt the key with the private idendity
        # Because pycryptodome doesn't support HPKE, using this very secure lib
        # https://github.com/dajiaji/pyhpke

        # Create the store key object ..
        # KEM
        pub_hpke_key = pyhpke.KEMKey.from_pem(
            private_identity.public_key.export_key(format="PEM")
        )

        aead_enc, sender_context = self._get_hpke_cipher_suite().create_sender_context(
            pub_hpke_key
        )
        ct_key_enc = sender_context.seal(key)

        store_key = Guarian(
            store_name, private_identity.fingerprint, aead_enc, ct_key_enc
        )

        # Because the store key is brand new, save it
        self._dao.save(store_key)

    def get_store_encryption_key(
        self, store_name: str, private_identity: PrivateIdentity
    ) -> bytes | None:
        store_key = self._dao.find(store_name, private_identity.fingerprint)
        if store_key is None:
            return None

        priv_hpke_key = pyhpke.KEMKey.from_pem(
            private_identity.private_key.export_key(format="PEM")
        )
        recipient_context = self._get_hpke_cipher_suite().create_recipient_context(
            store_key.aead_enc, priv_hpke_key
        )
        return recipient_context.open(store_key.key_enc)
