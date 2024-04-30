import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QComboBox, QTextEdit, QPushButton, QHBoxLayout, QScrollArea
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QObject, pyqtSignal
from AESDES import *
from RSA import *
from Crypto.Random import get_random_bytes
from ECC import *

blockCipherSelected = 'AES'
encryptionSelected = 'ECC'

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

        self.user1_input_widget = QWidget()
        self.user2_input_widget = QWidget()

        self.user1_input_layout = QHBoxLayout(self.user1_input_widget)
        self.user2_input_layout = QHBoxLayout(self.user2_input_widget)

        self.setup_user_inputs()
        self.setup_shared_widgets()

        self.start_button = QPushButton("Start Chat")
        self.start_button.clicked.connect(self.start_chat)

        self.layout.addWidget(self.log_label)
        self.layout.addWidget(self.scroll_area)
        self.layout.addWidget(self.user1_input_widget)
        self.layout.addWidget(self.user2_input_widget)
        self.layout.addWidget(self.log_area)
        self.layout.addWidget(self.start_button)

        self.user1_message_signal = MessageSignal()
        self.user2_message_signal = MessageSignal()

        self.user1_send_button.clicked.connect(self.send_message_user1)
        self.user2_send_button.clicked.connect(self.send_message_user2)

        self.user1_input_text.setEnabled(False)
        self.user2_input_text.setEnabled(False)
        self.user1_send_button.setEnabled(False)
        self.user2_send_button.setEnabled(False)

        self.user1_message_signal.message_received.connect(self.display_message_user1)
        self.user2_message_signal.message_received.connect(self.display_message_user2)

    def setup_user_inputs(self):
        # User 1 input
        self.user1_input_text = QTextEdit()
        self.user1_input_text.setFont(QFont("Arial", 10))
        self.user1_send_button = QPushButton("Send")

        self.user1_input_layout.addWidget(self.user1_input_text)
        self.user1_input_layout.addWidget(self.user1_send_button)

        # User 2 input
        self.user2_input_text = QTextEdit()
        self.user2_input_text.setFont(QFont("Arial", 10))
        self.user2_send_button = QPushButton("Send")

        self.user2_input_layout.addWidget(self.user2_input_text)
        self.user2_input_layout.addWidget(self.user2_send_button)

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

        global blockCipherSelected
        global encryptionSelected
        symmetric_key = get_random_bytes(16)
        self.start_button.setEnabled(False)
        self.user1_input_text.setEnabled(True)
        self.user2_input_text.setEnabled(True)
        self.user1_send_button.setEnabled(True)
        self.user2_send_button.setEnabled(True)


        if encryptionSelected == 'RSA':
            flagECC = 0
            RSAEncryption = RSA()
            user1_public_key, user1_private_key = RSAEncryption.GenerateCommunicationKeys()
            user2_public_key, user2_private_key = RSAEncryption.GenerateCommunicationKeys()
            encrypted_symmetric_key = RSAEncryption.RSAEncrypt(symmetric_key, RSAEncryption.SerializePublicKey(user2_public_key))
            decrypted_symmetric_key = RSAEncryption.RSADecrypt(encrypted_symmetric_key, RSAEncryption.SerializePrivKey(user2_private_key))
        else:
            flagECC = 1
            ECCEncryption = ECC()
            user1PrivKey, user1PubKey, user1SharedKey, user2PrivKey, user2PubKey, user2SharedKey = ECCEncryption.generateKeys()

        if blockCipherSelected == 'AES':
            pass
        else:
            pass




        print("Chat started")

    def send_message_user1(self):
        message = self.user1_input_text.toPlainText()
        encrypted_message = "Encrypted Message: " + message
        self.user2_message_signal.message_received.emit(message)
        self.user1_input_text.clear()

    def showInLog(self, text):
        self.log_area.append(text)


    def send_message_user2(self):
        message = self.user2_input_text.toPlainText()
        encrypted_message = "Encrypted Message: " + message
        self.user1_message_signal.message_received.emit(message)
        self.user2_input_text.clear()

    def display_message_user1(self, message):
        label = QLabel("<b>User 1:</b> " + message)
        label.setStyleSheet("background-color: #CFFFE5; padding: 5px; border: 1px solid #80C0A0; border-radius: 5px;")
        label.setWordWrap(True)
        self.chat_layout.addWidget(label)

    def display_message_user2(self, message):
        label = QLabel("<b>User 2:</b> " + message)
        label.setStyleSheet("background-color: #FFFFE0; padding: 5px; border: 1px solid #E0D090; border-radius: 5px;")
        label.setWordWrap(True)
        self.chat_layout.addWidget(label)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
