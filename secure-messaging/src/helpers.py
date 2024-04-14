import json
import logging
import os
import socket
from typing import Dict, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.base import CertificateSigningRequest

HEADER_LENGTH = 4


def parse_msg(client_socket: socket.socket)-> bytes:
    """
    reads the message and returns the payload = msg length

    :param client_socket: socket to recieve data from
    :return: payload in bytes
    """
    # step 1: read the first 4 bytes, to get the size of the msg
    header = client_socket.recv(HEADER_LENGTH)

    # TODO: check if header does not match msg size
    print("\n\nparse_msg header: ", header)
    msg_length = 0
    try:
        msg_length = int.from_bytes(header, byteorder="big")
        print(f"parse_msg msg_length : " , msg_length)
        # step 2: read the message only equal to the msg length
        payload = client_socket.recv(msg_length)
        print(f"parse_msg payload: ", payload)
        return payload
    except Exception as e:
        print(e)
        return b"0"


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

def encrypt_sign(key, payload: bytes, payload_type: bytes, sender: bytes) -> bytes:
    """
    Encrypts plaintext message, and prepares the final message in message format

    :param user: str user to send TO
    :param message: bytes plaintext message
    :return: obj in format
    """
    iv = os.urandom(16)
    cipher = Cipher(
        algorithm=algorithms.AES256(key),
        mode=modes.GCM(iv),
        backend=default_backend()
    )
    en = cipher.encryptor()
    encrypted_payload = en.update(payload) + en.finalize()
    signature = HMAC_sign(key, payload)
    print("\n\nfrom encrypt_sign iv", iv)
    print("from encrypt_sign payload: ", payload)
    print("from encrypt_sign encrypted payload", encrypted_payload)
    print("from encrypt_sign signature", signature)
    return iv + encrypted_payload + signature



def HMAC_sign(key , message: bytes) -> bytes:
    """
    Signs a message using HMAC always 32 BYTES

    :param user: user the message is for
    :param message: bytes to sign
    :return: signature in bytes
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def send(message, socket: socket.socket, *, convert_to_json=True):
    """
    Sends the message OBJECT to the socket.
    converts to json and encodes if convert_to_json is True

    :param message:
    :param socket:
    """
    if convert_to_json:
        message = json.dumps(message).encode()
    header = len(message).to_bytes(HEADER_LENGTH, byteorder="big")
    socket.send(header + message)

def create_csr(user_name: str, sk: RSAPrivateKey ) -> CertificateSigningRequest:
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, user_name)
                ]
            )
        )
    csr = csr_builder.sign(
            private_key=sk,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
    return csr


def decrypt_verify(message: bytes, key)-> str:
    iv = message[:16]
    signature = message[-32:]
    payload = message[16:-32]

    print("\n\nfrom decrypt_verify iv: ", iv)
    print("from decrypt_verify payload: ", payload) 
    print("from decrypt_verify signature: ", signature)

    # decrypt the decoded_message
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # start decrypting
    decrypted_payload = decryptor.update(payload)
    print("\n\nfrom decrypt_verify payload: ", decrypted_payload)
    # check signature 
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(payload)
    try:
        h.verify(signature)
        return decrypted_payload.decode()
    except InvalidSignature:
        return ""
