from dataclasses import dataclass


@dataclass
class StoreKey:
    store_name: str
    identity_fingerprint: str
    aead_enc: bytes
    key_enc: bytes
