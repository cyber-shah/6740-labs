import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def load_private_key_from_file(file_path: str):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # If your private key is encrypted, provide the password here
        )
    return private_key


def load_public_key_from_file(file_path: str):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend(),
        )
    return public_key


def create_key_pair(key_name: str):
    # Ensure the folder exists, if not create it
    if not os.path.exists("keys"):
        os.makedirs("keys")

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    print("from helpers")
    print(type(private_key))

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Write private key to file
    private_key_path = os.path.join("keys", f"{key_name}_sk.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    # Get public key
    public_key = private_key.public_key()

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write public key to file
    public_key_path = os.path.join("keys", f"{key_name}_pk.pem")
    with open(public_key_path, "wb") as f:
        f.write(public_pem)
