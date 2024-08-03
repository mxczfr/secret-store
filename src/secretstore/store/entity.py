from dataclasses import dataclass


@dataclass
class Store:
    """
    Store dataclass.
    Fields:
        - name: The store name
        - data: the dict that store all the data
    """

    name: str
    data: dict[str, str]


@dataclass
class EncryptedStore:
    """
    EncryptedStore dataclass.
    Fields:
        - name: The store name
        - ciphertext: The store encrypted data
        - nonce: The nonce used to encrypt the data
    """

    name: str
    ciphertext: bytes
    nonce: bytes
