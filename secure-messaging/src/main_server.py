import json
import logging
import socket
import threading
import time
from pathlib import Path
from collections import defaultdict
import random
import hashlib

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

logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


"""
types of messages:
    {
            msg_length: "",
            ---------- encrypted ----------
            command : "",
            sender: "",
            payload : "",
            ---------- encrypted ----------
            signature: ""
            }

    commands :  list
                login
                logout
                get_cert
"""



class Server:

    def __init__(
        self, pk_location: str, sk_location: str, port: int, ca: CA, p: int, g: int, logins
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

        self.logins = [(username, hashlib.sha3_512(p.encode()).hexdigest()) for username, p in logins]
        # map of individual params for client connections
        self.steps = defaultdict(int)
        self.bs = {}


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
        return certificate

    def accept_connections(self):
        """
        1. Starts listening on the server socket,
        2. spawns a new thread for each client -- handle_client
        """
        self.__server_socket.listen(5)
        logging.info(f"server listening at {self.SERVER_IP}:{self.SERVER_PORT}")
        try:
            while True:
                # Accept incoming connection
                connection, address = self.__server_socket.accept()
                logging.info(f" Connected {address}")

                # create a new thread to handle that
                client_thread = threading.Thread(
                    target=self.handle_client, args=(connection, address)
                )
                client_thread.start()
        except KeyboardInterrupt:
            logging.info("Server stopped.")

    def handle_client(self, connection: socket.socket, address):
        try:
            while True:
                buf = self.parse_msg(connection)
                if len(buf) == 0:
                    time.sleep(0.01)
                    continue

                val = json.loads(buf.decode())
                logging.info(f"recieved from client {address}: {val}")

                step = self.steps[address]
                if step == 1:
                    b = random.randint(1, p - 2)
                    self.bs[address] = b
                    response = {"val": (pow(self.g, b, self.p) + pow(self.g, w, self.p)) % self.p}
                    connection.send(json.dumps())

                self.steps[address] += 1

                time.sleep(0.1)
        except Exception as e:
            logging.error(e)
        pass

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
            logging.error(e)


if __name__ == "__main__":
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
        logins=[("AzureDiamond", "hunter2")]
    )
    server.accept_connections()
