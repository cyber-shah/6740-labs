import hashlib
import json
import logging
import random
import socket
import threading
import time
from collections import defaultdict
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import helpers
from CA_server import CA

"""
1. authenticate users, using id and pass
    Once authenticated, use store the session key:
    session_keys :
        { user1: key1, }

2. use the Session keys to encrypt the communication between the client and server
3. get certs for that user
3. list all active users
"""
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
        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_socket.bind((self.SERVER_IP, self.SERVER_PORT))
        # load the keys --------------------------------------------------------
        self.__server_pk = helpers.load_public_key_from_file(pk_location)
        self.__server_sk = helpers.load_private_key_from_file(sk_location)
        # SSL STUFF --------------------------------------------------------
        # instantiate a CA
        self.__ca = ca
        # create ssl context
        # get certs
        self.__request_cert()
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

    def __request_cert(self) -> x509.Certificate:
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, "server"),
                ]
            )
        )
        csr = csr_builder.sign(
            private_key=self.__server_sk,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        certificate = self.__ca.request_cert(csr)
        logger.info("got certificates for the server")
        return certificate

    def accept_connections(self):
        """
        1. Starts listening on the server socket,
        2. spawns a new thread for each client -- handle_client
        """
        self.__server_socket.listen(5)
        logger.info(f"server listening at {self.SERVER_IP}:{self.SERVER_PORT}")
        try:
            while True:
                # Accept incoming connection
                connection, address = self.__server_socket.accept()
                logger.info(f" Connected {address}")

                # create a new thread to handle that
                client_thread = threading.Thread(
                    target=self.handle_client, args=(connection, address)
                )
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("Server stopped.")

    def handle_client(self, connection: socket.socket, address):
        try:
            while True:
                buf = helpers.parse_msg(connection)
                if len(buf) == 0:
                    time.sleep(0.01)
                    continue

                logger.info(f"recieved from client {address}: {buf}")

                self.steps[address] += 1
                step = self.steps[address]
                if step == 1:
                    val = json.loads(buf.decode())
                    b = random.randint(1, p - 2)
                    username = val["username"]
                    g_a = val["g_a"]

                    login = [v for v in self.logins if v[0] == username]
                    assert len(login) <= 1
                    if len(login) == 0:
                        # someone tried to log in with a username we don't have
                        return

                    username, w = login[0]
                    self.bs[address] = b

                    u = random.randint(1, 2**127 - 1)
                    c = random.randint(1, 2**127 - 1)

                    response = {
                        "g_b_plus_g_w": (
                            pow(self.g, b, self.p) + pow(self.g, w, self.p)
                        )
                        % self.p,
                        "u": u,
                        "c": c,
                    }

                    # (g^b)^(a + uw) = ((g^a)(g^(uw)))^b.
                    # intermediate modulos are to avoid enormous intermediate values
                    K = pow(g_a * pow(g, u * w, self.p), b, self.p)
                    logger.info(f"server: computed shared key {K}")
                    self.initial_keys[connection] = (u, c, hashlib.sha3_256(str(K).encode()).digest())
                    self.send(connection, response)
                if step == 2:
                    iv = buf[:16]
                    buf = buf[16:]
                    (expected_u, expected_c, key) = self.initial_keys[connection]
                    cipher = Cipher(
                        algorithm=algorithms.AES256(key),
                        mode=modes.CBC(iv),
                    )
                    d = cipher.decryptor()
                    message = d.update(buf) + d.finalize()
                    assert len(message) == 800 + 16 + 16
                    p_k = message[0:800]
                    u = int.from_bytes(message[800:800 + 16])
                    c = int.from_bytes(message[800 + 16:800 + 32])

                    # nice try attackers!
                    assert u == expected_u and c == expected_c

                    pk = serialization.load_pem_public_key(p_k)
                    # we now have p_k. send back A{cert}

                time.sleep(0.1)
        except Exception as e:
            logger.error(e)

    def logout(self, client_username: str, client_address):
        pass

    def login(self, client_username: str):
        pass

    def parse_msg(self, client_socket: socket.socket):
        """
        ALL MESSAGES MUST PASS THROUGH THIS
        reads the message and returns the payload, DOES NOT DECRYPT

        :param client_socket: socket to recieve data from
        :return: payload in bytes
        """
        # step 1: read the header, to get the size of the msg
        header = client_socket.recv(helpers.HEADER_LENGTH)
        msg_length = 0
        try:
            msg_length = int.from_bytes(header, byteorder="big")
            # step 2: read the message only equal to the msg length
            payload = client_socket.recv(msg_length)
            return payload
        except Exception as e:
            logger.error(e)

    def send(self, socket, message):
        message = json.dumps(message).encode()
        header = len(message).to_bytes(helpers.HEADER_LENGTH, byteorder="big")
        socket.send(header + message)


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
        logins=[("AzureDiamond", "hunter2")],
    )
    server.accept_connections()
