from pathlib import Path
import yaml
import hashlib
import socket
import random

p = Path(__file__).parent.parent
with open(p / "config.yml") as config_file:
    config = yaml.safe_load(config_file)

server_port = config["server"]["port"]
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("localhost", server_port))

p = config["dh"]["p"]
g = config["dh"]["g"]

class Client:
    def __init__(self, password):
        self.password = hashlib.sha3_512(password.encode()).hexdigest()
        # TODO double check this range
        # https://www.ibm.com/docs/en/zvse/6.2?topic=overview-diffie-hellman
        self.a = random.randint(1, p - 2)
        socket.send(str(pow(g, self.a, p)).encode())

c = Client("hunter2")
