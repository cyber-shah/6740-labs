
import socket


def send_messages():
    # Define the server address and port
    SERVER_ADDRESS = '127.0.0.1'  # Change this to the server's IP address
    SERVER_PORT = 6789# Change this to the server's port

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect((SERVER_ADDRESS, SERVER_PORT))
        print("Connected to the server.")

        while True:
            # Send a message to the server
            message = input("Enter message to send (or press Ctrl+C to exit): ")
            client_socket.sendall(message.encode())

    except KeyboardInterrupt:
        print("Ctrl+C pressed. Closing the connection.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Close the socket
        client_socket.close()

# Start sending messages
send_messages()

