import argparse
import hashlib
import json
import random
import socket
from pathlib import Path

import yaml
import hashlib
import socket
import random
import json
import logging

import helpers

logging.basicConfig(
    filename="client.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class Client:
    def __init__(self, username, password, p, g, server_port):
        self.username = username

        self.w = int(hashlib.sha3_512(password.encode()).hexdigest(), 16)

        # FIXME: check if 'a' can stay the same for all diffie hellman exchanges

        # TODO double check this range
        # https://www.ibm.com/docs/en/zvse/6.2?topic=overview-diffie-hellman
        self.a = random.randint(1, p - 2)
        self.p = p
        self.g = g

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.connect(("localhost", server_port))

        self.handshake()

    def handshake(self):
        self.send({"g_a": pow(self.g, self.a, self.p), "username": self.username})

        # need a delay here maybe to ensure server sends response? seems fine
        # for me though
        response = helpers.parse_msg(self.server_socket)
        response = json.loads(response.decode())
        g_b_plus_g_w = response["g_b_plus_g_w"]
        u = response["u"]
        c = response["c"]

        g_b = (g_b_plus_g_w - pow(self.g, self.w, self.p)) % self.p

        K = pow(g_b, self.a + (u * self.w), self.p)
        logging.info(f"computed shared key {K}")

    def send(self, message):
        message = json.dumps(message).encode()
        header = len(message).to_bytes(helpers.HEADER_LENGTH, byteorder="big")
        self.server_socket.send(header + message)

    def login(self):
        pass

    def start_cli(self):
        pass

    def login(self):
        pass

    def start_cli(self):
        pass


p = Path(__file__).parent.parent
with open(p / "config.yml") as config_file:
    config = yaml.safe_load(config_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client for communicating with server")
    parser.add_argument("username", help="Your username")
    parser.add_argument("password", help="Your password")
    args = parser.parse_args()

    c = Client(
        args.username,
        args.password,
        p=config["dh"]["p"],
        g=config["dh"]["g"],
        server_port=config["server"]["port"],
    )

    # TODO: check if login is sucessful
    c.start_cli()
    # TODO: else ask for a new password
