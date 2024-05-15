import os
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from public_key_cryptosystem import *


class KeyManagement:
    def __init__(self, storage_file="key_storage.json"):
        self.storage_file = storage_file
        self.keys = {}
        self.load_keys()

    def load_keys(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, "r") as file:
                self.keys = json.load(file)

    def save_keys(self):
        with open(self.storage_file, "w") as file:
            json.dump(self.keys, file)

    def store_key(self, key_id, key):
        self.keys[key_id] = b64encode(key).decode("utf-8")
        self.save_keys()

    def retrieve_key(self, key_id):
        key_data = self.keys.get(key_id)
        if key_data:
            return b64decode(key_data)
        else:
            raise ValueError(f"No key found for ID '{key_id}'")

    def generate_and_store_key_pair(self, key_type, key_id):
        if key_type == "RSA":
            private_key, public_key = generate_rsa_key_pair()
        elif key_type == "ECC":
            private_key, public_key = generate_ecc_key_pair()
        else:
            raise ValueError("Invalid key type. Choose 'RSA' or 'ECC'.")

        # Convert keys to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self.store_key(f"{key_id}_private", private_key_pem)
        self.store_key(f"{key_id}_public", public_key_pem)

        return private_key, public_key

    def retrieve_key_pair(self, key_id):
        private_key = self.retrieve_key(f"{key_id}_private")
        public_key = self.retrieve_key(f"{key_id}_public")

        private_key_obj = serialization.load_pem_private_key(
            private_key, password=None, backend=default_backend()
        )
        public_key_obj = serialization.load_pem_public_key(
            public_key, backend=default_backend()
        )

        return private_key_obj, public_key_obj

    def generate_and_store_symmetric_key(self, key_id, key_size=32):
        symmetric_key = os.urandom(key_size)
        self.store_key(f"{key_id}_symmetric", symmetric_key)
        return symmetric_key

    def retrieve_symmetric_key(self, key_id):
        return self.retrieve_key(f"{key_id}_symmetric")
