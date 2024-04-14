import json
import socket


def send_messages():
    # Define the server address and port
    SERVER_ADDRESS = "127.0.0.1"  # Change this to the server's IP address
    SERVER_PORT = 6789  # Change this to the server's port

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect((SERVER_ADDRESS, SERVER_PORT))
        print("Connected to the server.")

        while True:
            # Get user input for the message
            message = input("Enter message to send (or press Ctrl+C to exit): ")

            # Create message dictionary
            msg_dict = {"payload_type": "text", "sender": "client", "payload": message}

            message = json.dumps(message).encode()
            header = len(message).to_bytes(helpers.HEADER_LENGTH, byteorder="big")
            self.server_socket.send(header + message)
            socket.send(header + message)

            json_message = json.dumps(msg_dict).encode()
            header = len(json_message).to_bytes(4, byteorder="big")

            # Send the JSON message to the server
            client_socket.sendall()

    except KeyboardInterrupt:
        print("Ctrl+C pressed. Closing the connection.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Close the socket
        client_socket.close()


# Start sending messages
send_messages()
