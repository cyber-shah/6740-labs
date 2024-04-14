import argparse
import hashlib
import json
import logging
import os
import random
import socket
import threading
from pathlib import Path
import base64

import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import helpers

logging.basicConfig(
    filename="client.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class Client:
    def __init__(self, username, password, p, g, rsa_e, server_port, ca, server, port):
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('localhost', self.port))

        self.username = username
        self.w = int(hashlib.sha3_512(password.encode()).hexdigest(), 16)

        # TODO double check this range
        # https://www.ibm.com/docs/en/zvse/6.2?topic=overview-diffie-hellman
        self.a = random.randint(1, p - 2)
        self.p = p
        self.g = g
        self.rsa_e = rsa_e

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.connect(("localhost", server_port))
        # store server's PK and CA's PK here, as trusted authorities
        # TODO: add server's keys here after auth
        self.session_keys = {
            "ca": {
                "PK": helpers.load_public_key_from_file(ca),
            },
            "server": {
                "PK": helpers.load_public_key_from_file(server),
                "key": b"JSH3y6F17l1bjhB8QUN0EwDMa7bCxiep",
                "socket": self.server_socket,
            },
        }

        self.cert = None

        self.handshake()
        assert self.cert is not None
        print("handshake successful")
        # TODO: if sucessful, create KEYS


    def accept_connections(self):
        self.socket.listen(5)
        try:
            while True:
                connection, address = self.socket.accept()
                # create a new thread to handle that
                client_thread = threading.Thread(
                    target=self.handle_client, args=(connection,)
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("Server stopped.")


    def handle_client(self, connection):
        try:
            while True:
                _ , port = connection.getpeername()
                message = helpers.parse_msg(connection)
                if not message:
                    print("Client closed the connection.")
                    break

                decrypted_message = helpers.decrypt_verify(message, b"JSH3y6F17l1bjhB8QUN0EwDMa7bCxiep")
                print(decrypted_message)

        except Exception as e:
            logger.error(e)

    def recieve_server(self):
        try:
            while True:
                message = helpers.parse_msg(self.server_socket)
                decrypted_message = helpers.decrypt_verify(message, b"JSH3y6F17l1bjhB8QUN0EwDMa7bCxiep")
                print(decrypted_message)
        except Exception as e:
            logger.error(e)


    def handshake(self):
        """
        1. sends g_a mod p
        2. computes Key K
        3. creates a PK SK pair
        4. sends it to the server
        5. completes the handshake
        """
        server_socket = self.session_keys["server"]["socket"]
        message = {"g_a": pow(self.g, self.a, self.p), "username": self.username}
        logger.info(f"sent g_a mod p")

        helpers.send(message, server_socket)

        response = helpers.parse_msg(self.server_socket)
        response = json.loads(response.decode())
        g_b_plus_g_w = response["g_b_plus_g_w"]
        u = response["u"]
        c = response["c"]

        g_b = (g_b_plus_g_w - pow(self.g, self.w, self.p)) % self.p

        # ---------------------- Shared key computed -------------------------------------------
        K = pow(g_b, self.a + (u * self.w), self.p)
        # convert to 256 bits for aes256
        key = hashlib.sha3_256(str(K).encode()).digest()
        # save it
        self.session_keys["server"]["key"] = key
        logging.info(f"computed shared key {K}")

        # ------------------------- create key pair -------------------------------
        self.sk_a = rsa.generate_private_key(
            public_exponent=self.rsa_e, key_size=4096, backend=default_backend()
        )
        self.pk_a = self.sk_a.public_key()

        pk_bytes = self.pk_a.public_bytes(
            serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert len(pk_bytes) == 800

        # ----------------------- create a Cert request -----------------------------------
        csr = helpers.create_csr(self.username, self.sk_a)
        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)

        iv = os.urandom(16)
        cipher = Cipher(
            algorithm=algorithms.AES256(key),
            mode=modes.CBC(iv),
        )
        en = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        message = (
            en.update(
                padder.update(
                    iv
                    + pk_bytes
                    + len(csr_bytes).to_bytes(2)
                    + csr_bytes
                    + u.to_bytes(16)
                    + c.to_bytes(16)
                )
                + padder.finalize()
            )
            + en.finalize()
        )
        helpers.send(message, server_socket, convert_to_json=False)

        # ----------------------- get cert back from server -----------------------------------
        buf = helpers.parse_msg(self.server_socket)
        iv = buf[:16]
        buf = buf[16:]
        cipher = Cipher(
            algorithm=algorithms.AES256(key),
            mode=modes.CBC(iv),
        )
        d = cipher.decryptor()
        cert_bytes = d.update(buf) + d.finalize()
        cert = x509.load_pem_x509_certificate(cert_bytes)
        self.cert = cert
        # TODO assert cert is certified by the server? need to read the server's cert for that
        # assert cert.verify_directly_issued_by()

    def start_cli(self):
        while True:
            user_input = input(">").split()

            # 1. parse the input
            command = user_input[0].lower()
            user_input = user_input[1:]
            if command == "list":
                self.send_client(["server"] + user_input)
                print(user_input)
                pass
            elif command == "send":
                self.send_client(user_input)
                # 1. set if session key with that user is already setup
                #       if already setup, use that to communicate
                # 2. else set it up
                pass
            elif command == "logout":
                pass
            else:
                print("invalid command")

    def send_client(self, input: list[str]) -> None:
        """
        Sends message in the following format

        :param input: input receieved from the cli
        """
        try:
            user = input[0]
            message = input[1:]
            joined_message = f" ".join(message)

            # 1. check if session key with that user is already setup
            if user in self.session_keys:
                message = helpers.encrypt_sign(
                        key = self.session_keys[user]["key"],
                        payload = joined_message.encode())
                helpers.send(message, self.session_keys[user]['socket'], convert_to_json=False)
            # 2. else set it up
            else:
                try:
                    # set it up
                    self.setup_keys(user)
                    # send the message
                    message = helpers.encrypt_sign(
                        key = self.session_keys[user]["key"],
                        payload = joined_message.encode())
                    helpers.send(message, self.session_keys[user]['socket'])

                except ConnectionError:
                    print(f"> cannot connect to {user}")

        except IndexError:
            raise ValueError

    def setup_keys(self, user: str):
        # we are A and user is B. ask the server for B's public key
        pk_b = self.get_public_key_for(user)

        # TODO get B's socket information from the server
        socket_b = ...
        a = random.randint(1, self.p - 2)
        g_a = pow(self.g, a, self.p)

        message = self.cert.public_bytes(serialization.Encoding.PEM) + g_a.to_bytes(
            2048
        )
        helpers.send(message, socket_b)

        # should get back PK_A{[cert_b, g^b mod p]_{SK_B}}
        response = helpers.parse_msg(socket_b)

        K = ...
        # use key to compute final challenge
        helpers.send(..., socket_b)

    def get_public_key_for(self, user) -> rsa.RSAPublicKey:
        """
        Requests the public key of user from the server. Must already be
        authenticated with the server.
        """
        self.send_client(["server", "list"])
        response = helpers.parse_msg(self.server_socket)
        message = helpers.decrypt_verify(response, self.session_keys["server"]["key"])
        users = json.loads(message)
        if user not in users:
            raise Exception(f"cannot talk to user {user} because the server does not know its public key. valid users: {users.keys()}")
        pk_bytes = base64.b64decode(users[user].encode("ascii"))
        return serialization.load_pem_public_key(pk_bytes)


    def logout(self):
        pass


p = Path(__file__).parent.parent
with open(p / "config.yml") as config_file:
    config = yaml.safe_load(config_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client for communicating with server")
    parser.add_argument("username", help="Your username")
    parser.add_argument("password", help="Your password")
    args = parser.parse_args()

    server_pk_location = p / config["server"]["pk_location"]
    ca_pk_location = p / config["ca"]["pk_location"]

    c = Client(
        args.username,
        args.password,
        p=config["dh"]["p"],
        g=config["dh"]["g"],
        rsa_e=config["rsa"]["e"],
        ca=ca_pk_location,
        server=server_pk_location,
        server_port=config["server"]["port"],
        port=random.randint(1000, 3000)
    )

    # TODO: check if login is sucessful
    c.start_cli()
    # TODO: else ask for a new password
