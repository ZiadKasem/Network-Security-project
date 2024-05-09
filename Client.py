import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel
import socket
import threading
from RSA import *
from Crypto.Random import get_random_bytes
from AESDES import *


blockCipherSelected = None
encryptionSelected = None
MyID = None
Other_User_PublicKey = None
ClientRSAObj = RSA()
varxDecoded = None
client_symmetric_key = None
ClientBlockCipherObj = BlockCipher()
private = None
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
        global varxDecoded, private
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
            try:
                # sending the public key
                public, private = ClientRSAObj.GenerateCommunicationKeys()
                varX = ClientRSAObj.SerializePublicKey(public)
                varxDecoded = varX.decode("utf-8")

                self.client_socket.send(varX)
                print("Public Key message sent\n")
            except Exception as e:
                print(f"client exception {e}")

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
                client_symmetric_key = get_random_bytes(16)


                if Other_User_PublicKey:
                    encrypted_symmetric_key = ClientRSAObj.RSAEncrypt(client_symmetric_key, Other_User_PublicKey)
                    #if blockCipherSelected == "AES":
                    full_message = f"{self.username}:{message}::::{encrypted_symmetric_key}"
                    plaintext = full_message.split("::::")[0]
                    print("\nplaintext ", plaintext)
                    encrypted_plaintext, tag, nonce = ClientBlockCipherObj.encrypt_AES_EAX(plaintext.encode("utf-8"), client_symmetric_key)
                    print(full_message)
                    print("jared ",encrypted_plaintext)
                    print("\ntag ",tag)
                    print("\nnonce ", nonce)
                    print("\nencrypted symmetric key ", encrypted_symmetric_key)

                    #self.client_socket.send(f"AES::::{encrypted_plaintext.decode('utf-8')}::::{tag.decode('utf-8')}::::{nonce.decode('utf-8')}::::{encrypted_symmetric_key}")

                    #print(f"AES::::{encrypted_plaintext.decode('utf-8')}::::{tag.decode('utf-8')}::::{nonce.decode('utf-8')}::::{encrypted_symmetric_key}")
                    #encrypted_message = "AES::::" + encrypted_plaintext.decode("utf-8") + "::::" + tag.decode("utf-8") + "::::" + nonce.decode("utf-8") + "::::" + encrypted_symmetric_key.decode("utf-8")
                    print("bos hena\n")
                    #print(encrypted_plaintext.decode("utf-8"))
                    #print("\nciphertext: ", encrypted_plaintext)
                    allVals = [encrypted_plaintext, tag, nonce, encrypted_symmetric_key]
                    data_bytes = b'::::'.join(allVals)
                    self.client_socket.sendall(data_bytes)

                else:
                    full_message = f"{self.username}:{message}::::null"
                    print(full_message)
                self.message_textedit.append(full_message.split("::::")[0])
                #self.client_socket.send(full_message.encode())

                self.message_entry.clear()
            else:
                self.message_textedit.append("Please enter a username and connect to the server first.")
        else:
            self.message_textedit.append("Please enter a message.")




    def receive_message(self):
        global Other_User_PublicKey
        global  varxDecoded, private
        while True:
            try:
                print("weselt gowa\n")
                data = self.client_socket.recv(1024).decode("utf-8")
                print(f"data is received {data}")
                if data == "PK":
                    self.client_socket.send("ACK".encode("utf-8"))
                if data == "PK":
                    content = self.client_socket.recv(1024)
                    print(f"content.decode {content.decode('utf-8')} and varxDecoded: {varxDecoded} ")
                    if content.decode("utf-8") != varxDecoded:
                        Other_User_PublicKey = content
                        print("Now I have other user key ",Other_User_PublicKey)
                    else:
                        print("Mafeesh 7d lessa\n")
                elif data == "Normal":
                    content = self.client_socket.recv(1024)
                    print(content.split(b'::::'))
                    myMsg = content.split(b'::::')
                    receivedEncryptedPlaintext =  myMsg[0]
                    receivedTag = myMsg[1]
                    receivedNonce = myMsg[2]
                    receivedEncryptedSymmetricKey = myMsg[3]

                    receivedSymmetricKey  = ClientRSAObj.RSADecrypt(receivedEncryptedSymmetricKey, ClientRSAObj.SerializePrivKey(private))
                    decryptedReceivedPlaintext = ClientBlockCipherObj.decrypt_AES_EAX(receivedEncryptedPlaintext,
                                                                                      receivedSymmetricKey,receivedNonce, receivedTag)
                    print(decryptedReceivedPlaintext.decode("utf-8"))

                    self.message_textedit.append(decryptedReceivedPlaintext.decode("utf-8"))


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