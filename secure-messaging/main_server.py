import argparse
import logging
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import helpers
from CA_server import CA

"""
1. register users, store id and pass
2. authenticate users, using id and pass
3. talk to the CA, get certs
4. list all active users
"""

logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class Server:

    def __init__(self, pk_location: str, sk_location: str, port: int, ca: CA) -> None:
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
        self.__context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # get certs
        self.__request_cert()
        self.__context.load_cert_chain(certfile="certs/server.pem", keyfile=sk_location)

    def __request_cert(self) -> x509.Certificate:
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, "shah"),
                ]
            )
        )
        csr = csr_builder.sign(
            private_key=self.__server_sk,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        return self.__ca.request_cert(csr)

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
                client_socket, client_address = self.__server_socket.accept()
                logging.info(f" Connected {client_address}")

                # create a new thread to handle that
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                )
                client_thread.start()
        except KeyboardInterrupt:
            logging.info("Server stopped.")

    def handle_client(self, client_socket: socket.socket, client_address):
        try:
            while True:
                # NOTE: wrap it inside SSL
                ssl_socket = self.__context.wrap_socket(
                    client_socket,
                    server_side=True,
                    do_handshake_on_connect=True,
                    server_hostname="server",
                )
                data = client_socket.recv(1024).decode().strip()
                logging.info(f"{client_address}: {data}")
        except Exception as e:
            logging.error(e)
        pass


if __name__ == "__main__":

    ps = argparse.ArgumentParser(description="Initialize server with sk and pk.")
    ps.add_argument("-Ssk", help="Path to PEM Secret/Private Key file.", required=True)
    ps.add_argument("-Spk", help="Path to PEM Public Key file.", required=True)
    ps.add_argument("-port", help="port to start server ", default=6789, required=False)
    ps.add_argument("-Csk", help="Path to PEM Secret/Private Key file.", required=True)
    ps.add_argument("-Cpk", help="Path to PEM Public Key file.", required=True)
    args = ps.parse_args()
    # create a CA
    ca = CA(pk_location=args.Cpk, sk_location=args.Csk)
    # create the server instance
    server = Server(pk_location=args.pk, sk_location=args.sk, port=args.port, ca=ca)
