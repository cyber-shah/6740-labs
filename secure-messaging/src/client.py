import argparse
import base64
import hashlib
import json
import logging
import os
import random
import socket
import threading
from collections import defaultdict
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

import helpers

logging.basicConfig(
    filename="client.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


"""
TODO:
    2. server returns a list with PKs, cache them
    3. HMAC in verify and decrypt
    4. signing inside handshake
    5. logout

    for liam : 1. if password is invalid, server throws error?
"""


class Client:
    def __init__(self, username, password, p, g, rsa_e, server_port, ca, server, port):
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("localhost", self.port))

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
                "key": "",
                "socket": self.server_socket,
                "port": server_port,
            },
        }
        self.port_to_username = {}

        self.cert = None
        self.threads = {}

        self.handshake_with_server()
        assert self.cert is not None
        print("handshake with server successful")

        self.steps = defaultdict(int)
        accept_connections_thread = threading.Thread(
            target=self.accept_connections, args=()
        )
        accept_connections_thread.start()
        self.threads["accepy"] = accept_connections_thread

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
                self.threads[address] = client_thread
        except KeyboardInterrupt:
            print("Server stopped.")

    def handle_client(self, connection):
        try:
            while True:
                _, port = connection.getpeername()
                if self.steps[port] < 2:
                    # this port hasn't fully authenticated yet. finish handshake
                    self.handshake_with_client(connection, port)
                    continue

                message = helpers.parse_msg(connection)
                if not message:
                    print("Client closed the connection.")
                    break

                user = self.port_to_username[port]
                if user is not None:
                    decrypted = helpers.decrypt_verify(
                        message, self.session_keys[user]["key"]
                    )
                    print(f"<< {user} : {decrypted}")

                else:
                    print(f"[{port}] {message}")

        except Exception as e:
            logger.error(e)

    def recieve_server(self):
        try:
            while True:
                # TODO: CACHE the list sent by the server
                message = helpers.parse_msg(self.server_socket)
                decrypted_message = helpers.decrypt_verify(
                    message, self.session_keys["server"]["key"]
                )
                json_decrypted = json.loads(decrypted_message)
                if "list" in decrypted_message:
                    self.session_keys.update(json_decrypted["list"])
                    user_names = list(self.session_keys.keys())
                    user_names.remove("server")
                    user_names.remove("ca")
                    user_names.remove(self.username)
                    print("<< List of active users: ", user_names)
                elif "update" in decrypted_message:
                    self.session_keys.update(json_decrypted["update"])
                    print("<< new user joined: ", list(json_decrypted["update"].keys()))

        except Exception as e:
            logger.error(e)

    def handshake_with_client(self, connection, port):
        buf = helpers.parse_msg(connection)
        self.steps[port] += 1
        step = self.steps[port]

        if step == 1:
            # we are B and A is trying to authenticate with us.
            # A has signed the message with our public key.
            message = helpers.rsa_decrypt(buf, self.sk_a)
            cert_a_bytes = message[:-256]
            # TODO verify this cert is valid and came from a
            cert_a = x509.load_pem_x509_certificate(cert_a_bytes)
            username = cert_a.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value
            pk_a, _port_a = self.get_public_key_and_port_for(username)

            g_a = int.from_bytes(message[-256:])

            b = random.randint(1, self.p - 2)
            g_b = pow(self.g, b, self.p)
            c = os.urandom(16)
            message = (
                self.cert.public_bytes(serialization.Encoding.PEM)
                + c
                + g_b.to_bytes(256)
            )
            K = pow(g_a, b, self.p)
            K = hashlib.sha3_256(str(K).encode()).digest()
            self.session_keys[username]["key"] = K
            message = helpers.rsa_encrypt(message, pk_a)
            self.port_to_username[port] = username
            self.session_keys[username]["challenge"] = c
            helpers.send(message, connection, convert_to_json=False)
        if step == 2:
            username = self.port_to_username[port]
            iv = buf[:16]
            buf = buf[16:]
            cipher = Cipher(
                algorithm=algorithms.AES256(self.session_keys[username]["key"]),
                mode=modes.CBC(iv),
            )
            d = cipher.decryptor()
            c = d.update(buf) + d.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            c = unpadder.update(c) + unpadder.finalize()
            assert c == self.session_keys[username]["challenge"]
            print(f"successfully mutually authenticated with port {port} as {username}")

    def handshake_with_server(self):
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
                    + self.port.to_bytes(16)
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
        unpadder = padding.PKCS7(128).unpadder()
        cert_bytes = unpadder.update(cert_bytes) + unpadder.finalize()
        cert = x509.load_pem_x509_certificate(cert_bytes)
        self.cert = cert
        # --------------------------------------------------------------------------------------
        #                       once done with handshake start recieving server
        # --------------------------------------------------------------------------------------
        server_thread = threading.Thread(target=self.recieve_server, args=())
        server_thread.start()
        self.threads["server"] = server_thread

        # TODO assert cert is certified by the server? need to read the server's cert for that
        # assert cert.verify_directly_issued_by()

    def start_cli(self):
        try:
            while True:
                user_input = input(">> ").split()
                # 1. parse the input
                command = user_input[0].lower()

                # check if its list
                if command == "list":
                    # convert it to "send <server> list"
                    self.send_client(["send", "server", "list"])
                elif command == "send":
                    # must be of the format "send <user> <message>"
                    self.send_client(["send", "server", "upadate"])
                    self.send_client(user_input)
                    # 1. set if session key with that user is already setup
                    #       if already setup, use that to communicate
                    # 2. else set it up
                    pass
                elif command == "logout":
                    self.logout()
                    print("bye!")
                    pass
                elif command == "exit":
                    self.logout()
                    print("bye!")
                elif command == "show":
                    print(self.session_keys)
                else:
                    print("invalid command")
        except KeyboardInterrupt:
            self.logout()
            print("bye!")

    def send_client(self, input: list[str]) -> None:
        """
        Sends message in the following format

        :param input: input receieved from the cli
        """
        try:
            user = input[1]
            message = input[2:]
            joined_message = f" ".join(message)

            # 1.check if user exissts
            if user not in self.session_keys:
                print(f'unknown user {user}. Run "list" to load users')
                return

            # 1. check if session key with that user is already setup
            if "key" in self.session_keys[user] and "socket" in self.session_keys[user]:
                encrypted_message = helpers.encrypt_sign(
                    key=self.session_keys[user]["key"], payload=joined_message.encode()
                )
                helpers.send(
                    encrypted_message,
                    self.session_keys[user]["socket"],
                    convert_to_json=False,
                )
            # 2. else set it up
            else:
                try:
                    self.setup_keys(user)

                    # send the message
                    message = helpers.encrypt_sign(
                        key=self.session_keys[user]["key"],
                        payload=joined_message.encode(),
                    )
                    helpers.send(
                        message,
                        self.session_keys[user]["socket"],
                        convert_to_json=False,
                    )

                except ConnectionError:
                    print(f"> cannot connect to {user}")

        except IndexError:
            raise ValueError

    def setup_keys(self, user: str):
        # we are A and user is B. ask the server for B's public key and port
        pk_b, port_b = self.get_public_key_and_port_for(user)

        socket_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_b.connect(("localhost", port_b))

        a = random.randint(1, self.p - 2)
        g_a = pow(self.g, a, self.p)

        message = self.cert.public_bytes(serialization.Encoding.PEM) + g_a.to_bytes(256)

        message = helpers.rsa_encrypt(message, pk_b)
        helpers.send(message, socket_b, convert_to_json=False)

        # should get back PK_A{[cert_b, g^b mod p]_{SK_B}}
        response = helpers.parse_msg(socket_b)
        message = helpers.rsa_decrypt(response, self.sk_a)

        # TODO verify cert is valid and came from b
        cert_b_bytes = message[: -256 - 16]
        c = message[-256 - 16 : -256]
        g_b = int.from_bytes(message[-256:])
        cert_b = x509.load_pem_x509_certificate(cert_b_bytes)
        username = cert_b.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert username == user, (username, user)
        K = pow(g_b, a, self.p)
        K = hashlib.sha3_256(str(K).encode()).digest()
        self.session_keys[username]["key"] = K
        self.session_keys[username]["socket"] = socket_b

        iv = os.urandom(16)
        cipher = Cipher(
            algorithm=algorithms.AES256(K),
            mode=modes.CBC(iv),
        )
        en = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        message = en.update(padder.update(iv + c) + padder.finalize()) + en.finalize()
        helpers.send(message, socket_b, convert_to_json=False)

    def get_public_key_and_port_for(self, user):
        """
        Requests the public key of user from the server. Must already be
        authenticated with the server.
        """
        base64_encoded_pk = self.session_keys[user]["PK"]
        decoded_pk = base64.b64decode(base64_encoded_pk)
        rsa_public_key = serialization.load_pem_public_key(
            decoded_pk, backend=default_backend()
        )
        return rsa_public_key, self.session_keys[user]["port"]

    def logout(self):
        for thread_name, thread in self.threads.items():
            thread.join()

    def get_username_from_port(self, port):
        for username, user_info in self.session_keys.items():
            if user_info.get("port") == port:
                return username
        return None


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
        port=random.randint(1000, 3000),
    )

    # TODO: check if login is sucessful
    c.start_cli()
    # TODO: else ask for a new password
