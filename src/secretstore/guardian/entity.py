from dataclasses import dataclass


@dataclass
class Guarian:
    store_name: str
    identity_fingerprint: str
    aead_enc: bytes
    key_enc: bytes
