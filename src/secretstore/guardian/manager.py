from typing import TYPE_CHECKING

import pyhpke

from secretstore.guardian.dao import GuardianDAO
from secretstore.guardian.entity import Guardian
from secretstore.identity.entity import PrivateIdentity

if TYPE_CHECKING:
    from sqlite3 import Connection
    from secretstore.identity.entity import PublicIdentity


class GuardianManager:
    """
    Guardian Manager. Handles all Guardian related actions.
    A guardian contains the store encryption key for a specific identity. 
    This key is encrypted with the public key of the identity.
    """

    def __init__(self, connection: "Connection"):
        """
        Initialize the Manager.

        :param connection: The sqlite connection to use
        """
        self._dao = GuardianDAO(connection)

    def _get_hpke_cipher_suite(self) -> pyhpke.CipherSuite:
        """Return the cipher suite to use for Hybrid Public Key Encryption"""
        return pyhpke.CipherSuite.new(
            pyhpke.KEMId.DHKEM_P256_HKDF_SHA256,
            pyhpke.KDFId.HKDF_SHA256,
            pyhpke.AEADId.AES256_GCM,
        )

    def create_guardian(self, store_name: str, identity: "PublicIdentity", key: bytes):
        """
        Create and save a guardian.

        :param store_name: The linked store name
        :param identity: The linked identity
        :param key: The key to securely store
        """
        # Encrypt the key with the public identity
        # Because pycryptodome doesn't support HPKE, using this very secure lib
        # https://github.com/dajiaji/pyhpke

        # Create the guardian object ..
        # KEM
        pub_hpke_key = pyhpke.KEMKey.from_pem(
            identity.public_key.export_key(format="PEM")
        )

        aead_enc, sender_context = self._get_hpke_cipher_suite().create_sender_context(
            pub_hpke_key
        )
        ct_enc_key = sender_context.seal(key)

        guardian = Guardian(store_name, identity.fingerprint, aead_enc, ct_enc_key)

        # Because the guardian is brand new, save it
        self._dao.save(guardian)

    def get_store_encryption_key(
        self, store_name: str, private_identity: PrivateIdentity
    ) -> bytes | None:
        """
        Retrieve and return a store encryption key stored in a guardian.

        :param store_name: The linked store name
        :param private_identity: The linked private_identity
        :return: The encryption key or None if nothing was found
        """
        guardian = self._dao.find(store_name, private_identity.fingerprint)
        if guardian is None:
            return None

        priv_hpke_key = pyhpke.KEMKey.from_pem(
            private_identity.private_key.export_key(format="PEM")
        )
        recipient_context = self._get_hpke_cipher_suite().create_recipient_context(
            guardian.aead_enc, priv_hpke_key
        )
        return recipient_context.open(guardian.enc_key)

    def find_stores_names(self, private_identities: list[PrivateIdentity]) -> list[str]:
        """
        Find all stores related to the specified private identities.

        :param private_identities: The list of private identities linked to stores
        :return: A list of stores names
        """
        return self._dao.find_stores_names(
            [id.fingerprint for id in private_identities]
        )

    def delete_store_guardians(self, store_name: str):
        """
        Delete all related guardians to a store

        :param store_name: The name of the store
        """
        self._dao.delete_store_guardians(store_name)
