import socket
import threading
from queue import Queue
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QComboBox, QPushButton, QTextEdit

# List to store connected clients
clients = []
# Global variables for block cipher and encryption method
blockCipherSelected = "AES"
encryptionSelected = "ECC"
connected_clients = 0
# Event to signal the server to stop
stop_server_event = threading.Event()
# Data storage for each client
client_data = []
PUBLICKEYEXECHANGED = 0


def PublicKeyExechange(decoded_client_public_key):
    global client_data, clients, PUBLICKEYEXECHANGED
    print(f"printing clients {clients}")
    for client in clients:
        try:
            client.send("PK".encode())

            ack = client.recv(1024).decode('utf-8')

            if ack == "ACK":

                if len(clients) > 1:

                    myIndex = clients.index(client)

                    if myIndex == 0:

                        client.send(client_data[1].encode("utf-8"))
                    else:

                        client.send(client_data[0].encode("utf-8"))
                else:
                    client.send(decoded_client_public_key.encode("utf-8"))
        except Exception as e:
            print(f"BCast Error{e}")
            clients.remove(client)
    if len(clients) == 2:
        PUBLICKEYEXECHANGED = 1


# Modify the handle_client function to send an update message when a new client connects
def handle_client(client_socket, client_address):
    global blockCipherSelected, encryptionSelected, connected_clients, client_data, PUBLICKEYEXECHANGED
    try:
        connected_clients += 1
        # Receive username from client
        username = client_socket.recv(1024).decode('utf-8')
        client_socket.send(f"{blockCipherSelected}:{encryptionSelected}:{connected_clients}".encode('utf-8'))
        try:

            # Receive PublicKey from client
            Client_Public_key = client_socket.recv(1024)

            client_data.append(Client_Public_key.decode("utf-8"))

            PublicKeyExechange(Client_Public_key.decode("utf-8"))
        except Exception as e:
            print(f"the receive exception error : {e}")

        # Prompt client for username
        print(f"Username '{username}' connected from {client_address}")
        # Add client address to connected clients list
        update_connected_clients(f"{username} - {client_address}")
        # Broadcast an update message to all clients

        while not stop_server_event.is_set():
            # Receive message from client
            while (PUBLICKEYEXECHANGED != 1):
                pass
            print("client is waiting for message to be send")

            try:
                message = client_socket.recv(1024)

            except Exception as e:
                print("Error da ", e)

            if not message:
                print(f"Connection with {client_address} closed.")
                break
            # Broadcast message to all clients
            broadcast(message, client_socket)
    except Exception as e:
        print(f"Error: {e}")
    # Remove client from the list of connected clients
    clients.remove(client_socket)
    connected_clients -= 1
    client_socket.close()


# Function to broadcast messages to all clients including the number of connected clients
def broadcast(message, client_socket):
    for client in clients:
        try:
            if client != client_socket:
                client.send("Normal".encode())

                client.sendall(message)
        except Exception as e:
            print(f"BCast Error{e}")
            clients.remove(client)


# Function to update the list of connected clients in the GUI
def update_connected_clients(client_info):
    window.update_connected_clients(client_info)


# Main function to set up server and accept incoming connections
def main():
    global blockCipherSelected, encryptionSelected
    host = '127.0.0.1'
    port = 5560
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind server socket to address
    server_socket.bind((host, port))
    # Listen for incoming connections
    server_socket.listen()
    print("Server listening on port:", port)
    while not stop_server_event.is_set():
        if len(clients) < 2:  # Limit the number of clients to 2
            # Accept incoming connection
            client_socket, client_address = server_socket.accept()
            # Add client to list of connected clients
            clients.append(client_socket)
            # Start a new thread to handle client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
        else:
            pass
    # Close the server socket when the server stops
    server_socket.close()


# GUI setup
class ServerConfigWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Server Configuration")
        self.layout = QVBoxLayout()
        self.setup_shared_widgets()
        self.setup_start_button()
        self.setup_connected_clients_area()
        self.setLayout(self.layout)

    def setup_shared_widgets(self):
        self.block_cipher_label = QLabel("Block Cipher Algorithm:")
        self.block_cipher_combo = QComboBox()
        self.block_cipher_combo.addItems(["AES", "DES"])
        self.block_cipher_combo.currentIndexChanged.connect(self.block_cipher_changed)
        self.crypto_system_label = QLabel("Crypto System Algorithm:")
        self.crypto_system_combo = QComboBox()
        self.crypto_system_combo.addItems(["ECC", "RSA"])
        self.crypto_system_combo.currentIndexChanged.connect(self.encryption_method_changed)
        self.layout.addWidget(self.block_cipher_label)
        self.layout.addWidget(self.block_cipher_combo)
        self.layout.addWidget(self.crypto_system_label)
        self.layout.addWidget(self.crypto_system_combo)

    def setup_start_button(self):
        self.start_button = QPushButton("Start Server")
        self.start_button.clicked.connect(self.start_server)
        self.layout.addWidget(self.start_button)

    def setup_connected_clients_area(self):
        self.connected_clients_label = QLabel("Connected Clients:")
        self.connected_clients_display = QTextEdit()
        self.connected_clients_display.setReadOnly(True)
        self.layout.addWidget(self.connected_clients_label)
        self.layout.addWidget(self.connected_clients_display)

    def block_cipher_changed(self, index):
        global blockCipherSelected
        blockCipherSelected = self.block_cipher_combo.currentText()

    def encryption_method_changed(self, index):
        global encryptionSelected
        encryptionSelected = self.crypto_system_combo.currentText()

    def start_server(self):
        global blockCipherSelected, encryptionSelected
        # Run the server in a separate thread
        server_thread = threading.Thread(target=main)
        print(f"{blockCipherSelected}, {encryptionSelected}")
        server_thread.start()

    def update_connected_clients(self, client_info):
        self.connected_clients_display.append(client_info)


if __name__ == "__main__":
    app = QApplication([])
    window = ServerConfigWindow()
    window.show()
    app.exec_()
