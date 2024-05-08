import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel
from PyQt5.QtCore import Qt
import socket
import threading
from RSA import *
from Hashing import *
import os
from KeyManager import *

blockCipherSelected = None
encryptionSelected = None
MyID = None

Other_User_PublicKey = None

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
            self.client_socket.connect(("127.0.0.1", 5560))

            # Send username to server
            self.client_socket.send(self.username.encode())
            PreConfig = self.client_socket.recv(1024).decode()
            print(PreConfig)
            blockCipherSelected = PreConfig.split(":")[0]
            encryptionSelected = PreConfig.split(":")[1]
            MyID = PreConfig.split(":")[2]
            print(f"{blockCipherSelected}, {encryptionSelected}")

            #sending the public key
            self.client_socket.send(f"{self.username}".encode('utf-8'))

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
        global Other_User_PublicKey
        while True:
            try:
                data = self.client_socket.recv(1024).decode()
                print(f"This iss the message {data}")
                message, num_clients= data.split('|')
                print(f"message.split(':')[0] is {message.split(':')[0]}  and self.username is {self.username}")
                #message formate is user:message  |  numberOfUsers%publicKey
                if (message.split(":")[0] != self.username and num_clients.split("%")[1] != self.username):#to be changed to public key
                    print(f"Entered")
                    self.message_textedit.append(message)
                    Other_User_PublicKey = num_clients.split("%")[1]
                    print(f"other user public key {Other_User_PublicKey}")
                # Update the number of connected clients label
                self.connected_clients_label.setText(f"Connected Clients: {num_clients.split('%')[0]}")
            except:
                print("An error occurred!")
                self.client_socket.close()
                break

    def Generating_RSA_Key(self):
        """
        pseudocode

        """
        print("Entering Generating_RSA_Key")
        RSAEncryption = RSA()
        # HashingObj = SHA_256()
        RSA_user1_public_key, RSA_user1_private_key = RSAEncryption.GenerateCommunicationKeys()
        RSA_user1_private_key_serialized = RSAEncryption.SerializePrivKey(RSA_user1_private_key)
        # RSA_user1_private_key_Hashed = HashingObj.hash_data(RSA_user1_private_key_serialized)
        # with open(f'{self.username}.txt', 'w') as userKeyFile:
        #     userKeyFile.write(str(RSA_user1_private_key_Hashed))
        return RSA_user1_public_key, RSA_user1_private_key


def main():
    app = QApplication(sys.argv)
    chat_app = ChatApp()
    chat_app.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()