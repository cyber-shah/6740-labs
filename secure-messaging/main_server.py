import argparse
import logging
import socket
import ssl
import threading

import helpers
from cert_server import CA

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

    def __init__(self, pk_location, sk_location, port) -> None:
        self.SERVER_PORT = port
        self.SERVER_IP = "localhost"
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.SERVER_IP, self.SERVER_PORT))
        # load secret and public keys
        self.context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        self.SERVER_PK = helpers.load_public_key_from_file(pk_location)
        self.SERVER_SK = helpers.load_private_key_from_file(sk_location)
        print(self.SERVER_PK)
        print(self.SERVER_SK)

    def accept_connections(self):
        """
        1. Starts listening on the server socket,
        2. spawns a new thread for each client -- handle_client
        """
        self.server_socket.listen(5)
        logging.info(
            f"server has started listening at {self.SERVER_IP}:{self.SERVER_PORT}"
        )
        try:
            while True:
                # Accept incoming connection
                client_socket, client_address = self.server_socket.accept()
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
                ssl_socket = self.context.wrap_socket(
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
    parser = argparse.ArgumentParser(
        description="Initialize the server with private and public keys."
    )
    parser.add_argument(
        "-sk", help="Path to the PEM Secret/Private Key file.", required=True
    )
    parser.add_argument("-pk", help="Path to the PEM Public Key file.", required=True)
    parser.add_argument(
        "-port", help="port to start the server at", default=6789, required=False
    )
    args = parser.parse_args()

    server = Server(pk_location=args.pk, sk_location=args.sk, port=args.port)
