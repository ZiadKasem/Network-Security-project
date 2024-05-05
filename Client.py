import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel
from PyQt5.QtCore import Qt
import socket
import threading

blockCipherSelected = None
encryptionSelected = None
MyID = None

class ChatApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Chat Application")
        self.init_ui()

        self.username = None

    def init_ui(self):
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.username_label = QLabel("Enter your username:")
        self.layout.addWidget(self.username_label)

        self.username_entry = QLineEdit()
        self.layout.addWidget(self.username_entry)

        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_to_server)
        self.layout.addWidget(self.connect_button)

        self.message_textedit = QTextEdit()
        self.layout.addWidget(self.message_textedit)

        self.entry_layout = QHBoxLayout()

        self.message_entry = QLineEdit()
        self.entry_layout.addWidget(self.message_entry)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.entry_layout.addWidget(self.send_button)

        self.layout.addLayout(self.entry_layout)

        # Add QLabel to display number of connected clients
        self.connected_clients_label = QLabel("Connected Clients: 0")
        self.layout.addWidget(self.connected_clients_label)

    def connect_to_server(self):
        global blockCipherSelected, encryptionSelected
        self.username = self.username_entry.text()
        if self.username:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(("127.0.0.1", 5555))

            # Send username to server
            self.client_socket.send(self.username.encode())
            PreConfig = self.client_socket.recv(1024).decode()
            print(PreConfig)
            blockCipherSelected = PreConfig.split(":")[0]
            encryptionSelected = PreConfig.split(":")[1]
            MyID = PreConfig.split(":")[2]
            print(f"{blockCipherSelected}, {encryptionSelected}")

            self.message_textedit.append("Connected to server!")
            self.connect_button.setEnabled(False)
            self.username_entry.setEnabled(False)

            receive_thread = threading.Thread(target=self.receive_message)
            receive_thread.start()
        else:
            self.message_textedit.append("Please enter a username.")

    def send_message(self):
        message = self.message_entry.text()
        if message:
            if self.username:
                full_message = f"{self.username}: {message}"
                self.message_textedit.append(full_message)
                self.client_socket.send(full_message.encode())
                self.message_entry.clear()
            else:
                self.message_textedit.append("Please enter a username and connect to the server first.")
        else:
            self.message_textedit.append("Please enter a message.")

    def receive_message(self):
        while True:
            try:
                data = self.client_socket.recv(1024).decode()
                message, num_clients = data.split('|')
                self.message_textedit.append(message)
                # Update the number of connected clients label
                self.connected_clients_label.setText(f"Connected Clients: {num_clients}")
            except:
                print("An error occurred!")
                self.client_socket.close()
                break


def main():
    app = QApplication(sys.argv)
    chat_app = ChatApp()
    chat_app.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
