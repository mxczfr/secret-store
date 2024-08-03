from dataclasses import dataclass


@dataclass
class Guardian:
    """
    Guardian dataclass.
    Fields:
        - store_name: the name of the store linked to this guardian
        - identity_fingerprint: the fingerprint of the private identity linked to this guardian
        - aead_enc: The authenticated encryption with additional data encapsulation
        - enc_key: The encryption key
    """

    store_name: str
    identity_fingerprint: str
    aead_enc: bytes
    enc_key: bytes
