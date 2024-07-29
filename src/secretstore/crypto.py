import os
from paramiko.agent import AgentKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionPack:
    SEED_SIZE = 16
    ENCRYPTION_KEY_SIZE = 32
    IV_SIZE = 16

    def __init__(self, key: "AgentKey", seed: bytes):
        r"""
        Generate all the necessary to encrypt / decrypt with aes from a AgentKey

        - 32 bytes encryption key<br>
        - 16 bytes IV

        :param seed: The seed used for the key derivation
        :param key: The key to sign the challenge.
        """
        self.seed = seed

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=EncryptionPack.ENCRYPTION_KEY_SIZE + EncryptionPack.IV_SIZE,
            salt=self.seed,
            iterations=390000,
        )
        kdf_key = kdf.derive(key.sign_ssh_data(seed))
        self.encryption_key = kdf_key[: EncryptionPack.ENCRYPTION_KEY_SIZE]
        self.iv = kdf_key[EncryptionPack.ENCRYPTION_KEY_SIZE :]

    @staticmethod
    def new(key: "AgentKey") -> "EncryptionPack":
        """
        Create an encryptionPack from scratch without provided seed.
        The seed will be generated and be EncryptionPack.SEED_SIZE long

        :param key: The key to sign the challenge:
        """
        return EncryptionPack(key, os.urandom(EncryptionPack.SEED_SIZE))

    @staticmethod
    def from_seed(key: "AgentKey", seed: bytes) -> "EncryptionPack":
        """
        Create an encryptionPack with a seed.

        :param key: The key to sign the challenge:
        :param seed: The seed used for the key derivation
        """
        return EncryptionPack(key, seed)
