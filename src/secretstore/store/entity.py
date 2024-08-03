from dataclasses import dataclass


@dataclass
class Store:
    name: str
    data: dict[str, str]


@dataclass
class EncryptedStore:
    name: str
    ciphertext: bytes
    nonce: bytes
