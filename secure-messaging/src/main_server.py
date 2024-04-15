import base64
import hashlib
import json
import logging
import os
import random
import socket
import threading
from collections import defaultdict
from io import BytesIO
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import helpers
from CA_server import CA

# TODO: whenever a new user joins update everyone


class Server:

    def __init__(
        self,
        pk_location: str,
        sk_location: str,
        port: int,
        ca: CA,
        p: int,
        g: int,
        logins,
    ) -> None:
        # some defaults first --------------------------------------------------------
        self.SERVER_PORT = port
        self.SERVER_IP = "localhost"
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.SERVER_IP, self.SERVER_PORT))
        # load the keys --------------------------------------------------------
        self.server_pk = helpers.load_public_key_from_file(pk_location)
        self.server_sk = helpers.load_private_key_from_file(sk_location)
        # instantiate a CA
        self.ca = ca
        self.p = p
        self.g = g

        self.logins = [
            (username, int(hashlib.sha3_512(p.encode()).hexdigest(), 16))
            for username, p in logins
        ]
        # map of individual params for client connections
        self.steps = defaultdict(int)
        self.bs = {}
        self.initial_keys = {}
        self.session_keys = defaultdict(dict)
        self.active_users = {}

    def accept_connections(self):
        """
        1. Starts listening on the server socket,
        2. spawns a new thread for each client -- handle_client
        """
        self.server_socket.listen(5)
        print(f"server listening at {self.SERVER_IP}:{self.SERVER_PORT}")
        try:
            while True:
                # Accept incoming connection
                connection, address = self.server_socket.accept()

                print(f" Connected {address}")

                # create a new thread to handle that
                client_thread = threading.Thread(
                    target=self.handle_client, args=(connection,)
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("Server stopped.")

    def handle_client(self, connection: socket.socket):
        try:
            while True:
                # if message is coming from a port that is not seen
                # ------------------------ do a handshake/authenticate ----------------------------
                _, port = connection.getpeername()
                if self.steps[port] < 2:
                    # this port hasn't fully authenticated yet. finish handshake
                    self.handshake(connection, port)
                    continue

                # ------------------------- post handshake ----------------------------------------
                message = helpers.parse_msg(connection)

                # If recv() returns an empty byte string, it means the client closed the connection
                if not message:
                    print("Client closed the connection.")
                    break

                # decrypt and verify
                decrypted_message = helpers.decrypt_verify(
                    message, self.session_keys[port]["key"]
                )

                # ------------------------- user requested list -------------------------------------
                if decrypted_message == "list":
                    new_message = {"list": self.active_users}
                    encrypted_message = helpers.encrypt_sign(
                        key=self.session_keys[port]["key"],
                        payload=json.dumps(new_message).encode(),
                    )
                    helpers.send(encrypted_message, connection, convert_to_json=False)
        except Exception as e:
            import traceback

            traceback.print_exception(e)
            logger.error(e)

    def handshake(self, connection: socket.socket, port):
        buf = helpers.parse_msg(connection)

        self.steps[port] += 1
        step = self.steps[port]

        # ----------------------------------- send b ----------------------------------
        if step == 1:
            val = json.loads(buf.decode())
            b = random.randint(1, p - 2)
            username = val["username"]
            g_a = val["g_a"]

            login = [v for v in self.logins if v[0] == username]
            assert len(login) <= 1
            if len(login) == 0:
                # someone tried to log in with a username we don't have
                raise Exception(f"invalid username {username}")

            username, w = login[0]
            self.bs[port] = b

            u = random.randint(1, 2**127 - 1)
            c = random.randint(1, 2**127 - 1)

            response = {
                "g_b_plus_g_w": (pow(self.g, b, self.p) + pow(self.g, w, self.p))
                % self.p,
                "u": u,
                "c": c,
            }

            # -------------------------------------- K computed ---------------------------------------------
            # (g^b)^(a + uw) = ((g^a)(g^(uw)))^b.
            # intermediate modulos are to avoid enormous intermediate values
            K = pow(g_a * pow(g, u * w, self.p), b, self.p)
            K = hashlib.sha3_256(str(K).encode()).digest()
            self.session_keys[port]["key"] = K

            self.initial_keys[connection] = (username, u, c, K)
            helpers.send(response, connection)

        if step == 2:
            iv = buf[:16]
            buf = buf[16:]
            (username, expected_u, expected_c, key) = self.initial_keys[connection]
            cipher = Cipher(
                algorithm=algorithms.AES256(key),
                mode=modes.CBC(iv),
            )
            d = cipher.decryptor()
            try:
                message = d.update(buf) + d.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                message = unpadder.update(message) + unpadder.finalize()
            except ValueError:
                print("client provided an incorrect password! (symmetric key disagreement)")
                return

            message = BytesIO(message)
            pk_bytes = message.read(800)
            csr_len = int.from_bytes(message.read(2))
            csr_bytes = message.read(csr_len)
            u = int.from_bytes(message.read(16))
            c = int.from_bytes(message.read(16))
            port = int.from_bytes(message.read(16))

            # nice try attackers!
            assert u == expected_u and c == expected_c

            csr = x509.load_pem_x509_csr(csr_bytes)
            cert = self.ca.request_cert(csr)

            # encrypt the cert with K and send it back to A
            iv = os.urandom(16)
            cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
            cipher = Cipher(
                algorithm=algorithms.AES256(key),
                mode=modes.CBC(iv),
            )
            en = cipher.encryptor()

            padder = padding.PKCS7(128).padder()
            message = (
                en.update(padder.update(iv + cert_bytes) + padder.finalize())
                + en.finalize()
            )
            helpers.send(message, connection, convert_to_json=False)

            # add this user's public key to the list so we can send it to users
            # who want to talk to a.
            # b64encode to make bytes serializable
            self.active_users[username] = {}
            self.active_users[username]["port"] = port
            self.active_users[username]["PK"] = base64.b64encode(pk_bytes).decode(
                "ascii"
            )
            # ---------------- send the entire list -------------------------------
            _, acutal_port = connection.getpeername()
            new_message = {"list": self.active_users}
            encrypted_message = helpers.encrypt_sign(
                key=self.session_keys[acutal_port]["key"],
                payload=json.dumps(new_message).encode(),
            )
            helpers.send(encrypted_message, connection, convert_to_json=False)
            self.send_all("hi")

            print(f"client successfully authenticated at {port} as {username}")

    def logout(self, client_username: str, client_address):
        pass

    def send_all(self, message: str):
        for ports in self.session_keys.keys():
            print(ports)


if __name__ == "__main__":
    logging.basicConfig(
        filename="server.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    p = Path(__file__).parent.parent
    with open(p / "config.yml") as config_file:
        config = yaml.safe_load(config_file)

    # Extract server parameters
    server_pk_location = p / config["server"]["pk_location"]
    server_sk_location = p / config["server"]["sk_location"]
    server_port = config["server"]["port"]

    # Extract CA parameters
    ca_pk_location = p / config["ca"]["pk_location"]
    ca_sk_location = p / config["ca"]["sk_location"]

    p = config["dh"]["p"]
    g = config["dh"]["g"]

    # create a CA
    ca = CA(pk_location=ca_pk_location, sk_location=ca_sk_location)

    # create the server instance
    server = Server(
        pk_location=server_pk_location,
        sk_location=server_sk_location,
        port=server_port,
        ca=ca,
        p=p,
        g=g,
        logins=[
            ("AzureDiamond", "hunter2"),
            ("liam", "superprivatepassworddontpeek"),
            ("melt", "system"),
        ],
    )
    server.accept_connections()
