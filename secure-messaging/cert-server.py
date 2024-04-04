import socket
import threading


SERVER_PORT = 5555
SERVER_IP = "127.0.0.1"

"""
-----------------------------------------------------------------------------

The server needs to be able to do the following:
1. Manage users and passwords (create, update and delete)
2. Authenticate users using SRP
4. Maintain users PK and SK (create and update(in case they are leaked))
5. Maintain Certificates (create, delete and update)

-------------------------------------------------------------------------------
"""


def receive_messages(sock):
    while True:
        message = sock.recv(1024).decode()
        print(f"Received: {message}")


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((SERVER_IP, SERVER_PORT))
sock.listen()

print("waiting for connection")
connection, address = sock.accept()
print(f"connected to {connection} and {address}")

# Start a thread to receive messages
receive_thread = threading.Thread(target=receive_messages, args=(connection,))
receive_thread.start()

# Main loop for sending messages
while True:
    message = input("Enter your message: ")
    connection.sendall(message.encode())
