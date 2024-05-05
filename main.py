import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QComboBox, QTextEdit, QPushButton, QHBoxLayout, QScrollArea
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QObject, pyqtSignal
from AESDES import *
from RSA import *
from Crypto.Random import get_random_bytes
from ECC import *
from PyQt5.QtCore import pyqtSignal, QObject


blockCipherSelected   = 'AES'
encryptionSelected    = 'ECC'
RSA_user1_public_key  = ""
RSA_user1_private_key = ""
RSA_user2_public_key  = ""
RSA_user2_private_key = ""
user1PrivKey          = ""
user1PubKey           = ""
user1SharedKey        = ""
user2PrivKey          = ""
user2PubKey           = ""
user2SharedKey        = ""
RSAEncryption         = RSA()


class MessageSignal(QObject):
    message_received = pyqtSignal(str)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat App")
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)

        self.chat_widget = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_widget)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.chat_widget)

        self.log_label = QLabel("Chat:")
        self.log_label.setStyleSheet("font-weight: bold;")

        self.log_area = QTextEdit()
        self.log_area.setFont(QFont("Arial", 12))
        self.log_area.setReadOnly(True)

        self.user_input_widget = QWidget()
        self.user_input_layout = QHBoxLayout(self.user_input_widget)

        self.setup_user_input()
        self.setup_shared_widgets()

        self.start_button = QPushButton("Start Chat")
        self.start_button.clicked.connect(self.start_chat)

        self.layout.addWidget(self.log_label)
        self.layout.addWidget(self.scroll_area)
        self.layout.addWidget(self.user_input_widget)
        self.layout.addWidget(self.log_area)
        self.layout.addWidget(self.start_button)

        self.user_message_signal = MessageSignal()

        self.user_send_button.clicked.connect(self.send_message_user)

        self.user_input_text.setEnabled(False)
        self.user_send_button.setEnabled(False)

        self.user_message_signal.message_received.connect(self.receive_message_user)

        self.block_cipher = BlockCipher()

    def setup_user_input(self):
        # User input
        self.user_input_text = QTextEdit()
        self.user_input_text.setFont(QFont("Arial", 10))
        self.user_send_button = QPushButton("Send")

        self.user_input_layout.addWidget(self.user_input_text)
        self.user_input_layout.addWidget(self.user_send_button)

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

    def block_cipher_changed(self, index):
        global blockCipherSelected
        blockCipherSelected = self.block_cipher_combo.currentText()
        print(blockCipherSelected)

    def encryption_method_changed(self, index):
        global encryptionSelected
        encryptionSelected = self.crypto_system_combo.currentText()
        print(encryptionSelected)

    def start_chat(self):

        global blockCipherSelected, encryptionSelected
        global RSA_user1_public_key,RSA_user1_private_key,\
            RSA_user2_public_key, RSA_user2_private_key, user1PrivKey, user1PubKey,user1SharedKey, user2PrivKey, user2PubKey, user2SharedKey


        self.start_button.setEnabled(False)
        self.user_input_text.setEnabled(True)
        self.user_send_button.setEnabled(True)


        if encryptionSelected == 'RSA':
            global RSAEncryption
            RSA_user1_public_key, RSA_user1_private_key = RSAEncryption.GenerateCommunicationKeys()
            RSA_user2_public_key, RSA_user2_private_key = RSAEncryption.GenerateCommunicationKeys()


        else:
            encryptionSelected = 'ECC'
            ECCEncryption = ECC()
            user1PrivKey, user1PubKey, user1SharedKey, user2PrivKey, user2PubKey, user2SharedKey = ECCEncryption.generateKeys()

        print("Chat started")

    def send_message_user(self):
        message = self.user_input_text.toPlainText()
        encrypted_message = "Encrypted Message: " + message
        self.user_message_signal.message_received.emit(encrypted_message)
        self.user_input_text.clear()

    def showInLog(self, text):
        self.log_area.append(text)

    def receive_message_user(self, message):
        label = QLabel("<b>User:</b> " + message)
        label.setStyleSheet("background-color: #CFFFE5; padding: 5px; border: 1px solid #80C0A0; border-radius: 5px;")
        label.setWordWrap(True)
        self.chat_layout.addWidget(label)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
