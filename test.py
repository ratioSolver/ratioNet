import socket
import ssl

# Define the host and port for the server
HOST = "localhost"
PORT = 443  # Typically, SSL servers run on port 443

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the host and port
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen(5)

print(f"Server is listening on {HOST}:{PORT}...")

# Create an SSL context
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

# Load a self-signed certificate and private key
ssl_context.load_cert_chain(certfile="tests/cert.pem", keyfile="tests/key.pem")

while True:
    # Accept incoming connections
    client_socket, client_address = server_socket.accept()

    # Wrap the socket with SSL
    ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)

    print(f"Accepted connection from {client_address}")

    # Handle the client request (in this example, we'll just echo back)
    data = ssl_socket.recv(1024)
    if data:
        print(f"Received data from client: {data.decode('utf-8')}")
        ssl_socket.sendall(data)  # Echo the data back to the client

    # Close the connection
    ssl_socket.close()
