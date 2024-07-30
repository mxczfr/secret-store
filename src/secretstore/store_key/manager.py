from typing import TYPE_CHECKING
from secretstore.identity.entity import PrivateIdentity
from secretstore.store.entity import Store
from secretstore.store_key.dao import StoreKeyDAO
from secretstore.store_key.entity import StoreKey

import pyhpke

if TYPE_CHECKING:
    from sqlite3 import Connection

class StoreKeyManager:
    def __init__(self, connection: "Connection"):
        self._dao = StoreKeyDAO(connection)

    def _get_hpke_cipher_suite(self) -> pyhpke.CipherSuite:
       return  pyhpke.CipherSuite.new(
            pyhpke.KEMId.DHKEM_P256_HKDF_SHA256,
            pyhpke.KDFId.HKDF_SHA256,
            pyhpke.AEADId.AES256_GCM
        )

    def create_store_key(self, store: Store, private_identity: PrivateIdentity, key: bytes):
        # Encrypt the key with the private idendity
        # Because pycryptodome doesn't support HPKE, using this very secure lib 
        # https://github.com/dajiaji/pyhpke



        # Create the store key object ..
        pyhpke.cipher_suite = self._get_hpke_cipher_suite()
        # KEM
        pub_hpke_key= pyhpke.KEMKey.from_pem(private_identity.public_key.export_key(format="PEM"))

        aead_enc, sender_context = self._get_hpke_cipher_suite().create_sender_context(pub_hpke_key)
        ct_key_enc = sender_context.seal(key)

        store_key = StoreKey(store.name, private_identity.fingerprint, aead_enc, ct_key_enc)

        # Because the store key is brand new, save it 
        self._dao.save(store_key)
        # else:
        #     # decrypt the key
        #     priv_hpke_key = pyhpke.KEMKey.from_pem(private_identity.private_key.export_key(format="PEM"))
        #     recipent = self._get_hpke_cipher_suite().create_recipient_context(store_key.aead_enc, priv_hpke_key)
        #     key = recipent.open(store_key.key_enc)


        



       

