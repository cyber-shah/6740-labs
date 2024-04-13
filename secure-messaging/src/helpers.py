from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import socket
import logging

HEADER_LENGTH = 4


def parse_msg(client_socket: socket.socket):
    """
    ALL MESSAGES MUST PASS THROUGH THIS
    reads the message and returns the payload, DOES NOT DECRYPT

    :param client_socket: socket to recieve data from
    :return: payload in bytes
    """
    # step 1: read the header, to get the size of the msg
    header = client_socket.recv(HEADER_LENGTH)
    msg_length = 0
    try:
        msg_length = int.from_bytes(header, byteorder="big")
        # step 2: read the message only equal to the msg length
        payload = client_socket.recv(msg_length)
        return payload
    except Exception as e:
        logging.error(e)


def load_private_key_from_file(file_path: str) -> rsa.RSAPrivateKey:
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # If your private key is encrypted, provide the password here
        )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Not RSAPrivateKey")
    return private_key


def load_public_key_from_file(file_path: str) -> rsa.RSAPublicKey:
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend(),
        )
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Not RSAPrivateKey")
    return public_key


def read_cert(certificate: x509.Certificate):
    # Extract the public key from the certificate
    public_key = certificate.public_key()

    # Convert the public key to a string representation
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    print(
        f"Issuer: {certificate.issuer}, "
        f"Subject: {certificate.subject}, "
        f"Serial Number: {certificate.serial_number}, "
        f"Public Key: {public_key_str}"
    )

    pass
