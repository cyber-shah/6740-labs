import hashlib
import json
import logging
import os
import random
import socket
import threading
import time
from collections import defaultdict
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.base import CertificateSigningRequest

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
        self.session_keys = {}
        self.active_users = {}

    def accept_connections(self):
        """
        1. Starts listening on the server socket,
        2. spawns a new thread for each client -- handle_client
        """
        self.server_socket.listen(1)
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
                _ , port = connection.getpeername()
                # if port not in self.session_keys and self.steps[port] != 2:
                #     self.handshake(connection, port)
 
                # ------------------------- post handshake ----------------------------------------
                message = helpers.parse_msg(connection)

                # If recv() returns an empty byte string, it means the client closed the connection
                if not message:
                    print("Client closed the connection.")
                    break

                # decrypt and verify
                # decrypted_message = helpers.decrypt_verify(message, self.session_keys[port]["key"])
                decrypted_message = helpers.decrypt_verify(message, b"JSH3y6F17l1bjhB8QUN0EwDMa7bCxiep")
                print(decrypted_message)
                
                # ------------------------- user requested list -------------------------------------
                if decrypted_message is not None and decrypted_message["payload_type"] == "list":
                    message = helpers.encrypt_sign(key = self.session_keys[port]["key"],
                                                   payload = str(self.active_users).encode(),
                                                   payload_type="list".encode(),
                                                   sender="server".encode())
                    helpers.send(message, connection)
        except Exception as e:
            logger.error(e)

    def handshake(self, connection: socket.socket, port):
        buf = helpers.parse_msg(connection)

        print(f"recieved from client {port} : {buf}")

        self.steps[port] += 1
        step = self.steps[port]

        print(f"steps", step)
        # TODO: check if successful
        # ----------------------------------- send b ----------------------------------
        if step == 1:
            print("in step 1")
            val = json.loads(buf.decode())
            print(f"from val" + val)
            b = random.randint(1, p - 2)
            username = val["username"]
            g_a = val["g_a"]

            login = [v for v in self.logins if v[0] == username]
            assert len(login) <= 1
            if len(login) == 0:
                # someone tried to log in with a username we don't have
                return

            username, w = login[0]
            self.bs[port] = b

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

            # -------------------------------------- K computed ---------------------------------------------
            K = pow(g_a * pow(g, u * w, self.p), b, self.p)
            self.session_keys[port]["key"] = K
            print(f"server: computed shared key {K}")

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
            # we now have pk_a. send back K{cert}

            time.sleep(0.1)

    def logout(self, client_username: str, client_address):
        pass

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
