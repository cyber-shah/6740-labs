import socket
import threading

from cert_server import CA

"""
Server:
---------------------------------------------------------------------------
    By design the server doesn't know who talks to whom. They are only responsible for auth/reg users.
    1. all connections MUST be wrapped around TLS.
    2. registers/auths users
    3. manages user's PK and SK in a LUKS manner
    4. list all online users


Certificates:
---------------------------------------------------------------------------
    Cert generation is taken care by CA.
    for added security : ONLY the server can talk to the CA
    certificates are created for 24 hours

PK SK pair:
---------------------------------------------------------------------------
    Each user's PK SK pairs are stored on the server and will be sent to the user after auths
    stored using server's SK, along with the username and password

Client:
---------------------------------------------------------------------------
    Use message queues to store messages while someone is away?
    Each client trusts only one party and that is the CA
    PK and SK sent by the server is stored using TLS key. MUST be forgotten as the user logs out.
    TODO: protect the PK and SK from leaking WHILE the user is using the application

"""


class Server:

    def accept_connections(self):
        pass
