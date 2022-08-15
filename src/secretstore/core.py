import json
import os
import re
from pathlib import Path
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from paramiko.agent import Agent

from secretstore.exceptions import SSHKeyNotFound


class Store:
    """
    Store object. Can contain many fields related to one account / secret
    """

    def __init__(self, name: str, fields: dict = None):
        """
        Create the secret store
        :param name: The store name
        :param fields: The secret fields
        """
        Store.verify_name(name)
        self.name = name
        if fields is None:
            self.fields = {}
        else:
            self.fields = fields

    def add_field(self, key: str, value: str):
        """
        Add a field into the store
        :param key: The field key
        :param value: The field value
        """
        self.fields[key] = value

    def get_field(self, key: str) -> str:
        """
        Retrieve a field
        :param key: The field key
        :return: The field value
        """
        return self.fields[key]

    def to_json(self) -> str:
        """
        Convert the store as json
        :return: The json dump of the store
        """
        return json.dumps({"name": self.name, "fields": self.fields})

    @classmethod
    def from_json(cls, json_data: str):
        """
        Load a store from a json string
        :param json_data: The json string
        :return: The loaded store instance
        """
        json_store = json.loads(json_data)
        return Store(json_store["name"], json_store["fields"])

    @staticmethod
    def verify_name(name: str):
        """
        Verify if the store name is valid
        :param name: The name to validate
        :raise ValueError: If the name is invalid
        """
        regex_pattern = r"^[a-zAZ0-9]\w*[a-zAZ0-9]$"
        match = re.match(regex_pattern, name)
        if match is None:
            raise ValueError(f"Store name must match the regex pattern: {regex_pattern}")


class SecretStoreManager:
    """
    The Store Store Manager handle all secret store manipulation and encryption
    """

    def __init__(self):
        """
        Initialise the secret store manager
        """
        agent = Agent()

        keys = agent.get_keys()
        if len(keys) == 0:
            raise SSHKeyNotFound()
        self._key = keys[0]
        self._root = Path.home().joinpath(".secretstore", self._key.get_fingerprint().hex())

    def exists(self, name: str) -> bool:
        """
        Is the secret store exists
        :param name: The secret store name
        :return: True if the store exists
        """
        return self._root.joinpath(name).exists()

    def list(self) -> List[str]:
        """
        List all secret stores linked to the loaded ssh key
        :return: A list of all secret stores found
        """
        return [i.name for i in self._root.iterdir() if i.is_file()]

    def save(self, store: Store):
        """
        Save and encrypt a secret store
        :param store: The store to save
        """
        seed = os.urandom(16)
        encryption_key, iv = self._get_encryption_needs(seed)

        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(store.to_json().encode("utf-8"))
        padded_data += padder.finalize()

        encrypted_store = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_store += seed

        if not self._root.exists():
            self._root.mkdir(mode=0o770, parents=True, exist_ok=True)
        with self._root.joinpath(store.name).open(mode="wb") as f:
            f.write(encrypted_store)

    def load(self, name: str) -> Store:
        """
        Load and decrypt a secret store
        :param name: The secret store to load
        :return: The store
        """
        with self._root.joinpath(name).open(mode="rb") as f:
            encrypted_store = f.read()
        padded_data = encrypted_store[:-16]
        seed = encrypted_store[-16:]

        encryption_key, iv = self._get_encryption_needs(seed)

        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        data = decryptor.update(padded_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(data)
        unpadded_data += unpadder.finalize()

        return Store.from_json(unpadded_data.decode("utf-8"))

    def delete(self, name: str):
        """
        Delete a secret store
        :param name: The secret store name
        """
        self._root.joinpath(name).unlink()

    def _get_encryption_needs(self, seed: bytes = None) -> Tuple[bytes, bytes]:
        """
        Generate the store encryption needs from a seed.\n
        - 32 bytes encryption key<br>
        - 16 bytes IV
        :param seed: The seed used for the key derivation
        :return: The encryption key and the Initialization Vector
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32 + 16,
            salt=seed,
            iterations=390000,
        )
        kdf_key = kdf.derive(self._key.sign_ssh_data(seed))
        return kdf_key[:32], kdf_key[32:]
