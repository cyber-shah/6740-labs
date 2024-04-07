from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def load_private_key_from_file(file_path: str):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # If your private key is encrypted, provide the password here
            backend=default_backend(),
        )
    return private_key


def load_public_key_from_file(file_path: str):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend(),
        )
    return public_key
