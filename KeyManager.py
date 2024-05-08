# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.fernet import Fernet
# import base64
# from RSA import *
# def encrypt_public_key(public_key, passphrase = "your_secure_passphrase"):
#     salt = b'my_hardcoded_salt' # Hardcoded salt value
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000,
#         backend=default_backend()
#     )
#     key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
#     cipher = Fernet(key)
#     serialized_public_key = public_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     encrypted_public_key = cipher.encrypt(serialized_public_key)
#     return encrypted_public_key
#
# def decrypt_private_key(encrypted_private_key, passphrase = "your_secure_passphrase"):
#     salt = b'my_hardcoded_salt' # Hardcoded salt value
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000,
#         backend=default_backend()
#     )
#     key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
#     cipher = Fernet(key)
#     decrypted_private_key = cipher.decrypt(encrypted_private_key)
#     return decrypted_private_key
#
# def encrypt_private_key(private_key, passphrase):
#     salt = b'my_hardcoded_salt' # Hardcoded salt value
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000,
#         backend=default_backend()
#     )
#     key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
#     cipher = Fernet(key)
#     serialized_private_key = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     encrypted_private_key = cipher.encrypt(serialized_private_key)
#     return encrypted_private_key
#
# def decrypt_private_key(encrypted_private_key, passphrase):
#     salt = b'my_hardcoded_salt' # Hardcoded salt value
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000,
#         backend=default_backend()
#     )
#     key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
#     cipher = Fernet(key)
#     decrypted_private_key = cipher.decrypt(encrypted_private_key)
#     return decrypted_private_key
#
# TheRSA = RSA()
# # Generate RSA private key
# public_key, private_key = TheRSA.GenerateCommunicationKeys()
#
# # Example passphrase
# passphrase = "your_secure_passphrase"
#
# # Print the private key before encryption
# print("Private Key before encryption:")
# print(private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.TraditionalOpenSSL,
#     encryption_algorithm=serialization.NoEncryption()
# ).decode())
#
# # Encrypt the private key
# encrypted_private_key = encrypt_private_key(private_key, passphrase)
#
# # Print the encrypted private key
# print("\nEncrypted Private Key:")
# print(encrypted_private_key)
#
# # Write the encrypted private key to a file
# with open("encrypted_private_key.txt", "wb") as file:
#     file.write(encrypted_private_key)
#
# # Read the encrypted private key from the file
# with open("encrypted_private_key.txt", "rb") as file:
#     encrypted_private_key_read = file.read()
#
# # Decrypt the private key
# decrypted_private_key = decrypt_private_key(encrypted_private_key_read, passphrase)
#
# # Print the decrypted private key
# print("\nDecrypted Private Key:")
# print(decrypted_private_key.decode())

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
from RSA import *

class KeyManager:

    def __init__(self):
        pass


    def encrypt_key(self,key, passphrase = "your_secure_passphrase"):
        salt = b'my_hardcoded_salt' # Hardcoded salt value
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key_bytes = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) if isinstance(key, rsa.RSAPublicKey) else key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        key_encryption_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        cipher = Fernet(key_encryption_key)
        encrypted_key = cipher.encrypt(key_bytes)
        return encrypted_key

    def decrypt_key(self,encrypted_key, passphrase = "your_secure_passphrase"):
        salt = b'my_hardcoded_salt' # Hardcoded salt value
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key_encryption_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        cipher = Fernet(key_encryption_key)
        decrypted_key_bytes = cipher.decrypt(encrypted_key)
        return decrypted_key_bytes

    def storeEncryptedKeys(self,file_path, encrypted_public_key,encrypted_private_key):
        # Write the encrypted keys to a file
        try:
            print('5araaaaaa')
            with open(file_path, "wb") as file:
                file.write(encrypted_private_key + b'\n\n' + encrypted_public_key)
        except Exception as e:
            print(f"\nAn error occurred: {e}")


    def readEncryptedKeys(self,file_path):
        with open(f"{file_path}", "rb") as file:
            encrypted_private_key_read, encrypted_public_key_read = file.read().split(b'\n\n')
        return encrypted_public_key_read, encrypted_private_key_read

        # Read the encrypted keys from the file

    def checkAfterDecryption(self,decrypted_private_key, decrypted_public_key):
        print("\nDecrypted Private Key:")
        print(decrypted_private_key.decode())

        # Print the decrypted public key
        print("\nDecrypted Public Key:")
        print(decrypted_public_key.decode())






# # Encrypt the private key
# encrypted_private_key = encrypt_key(private_key, passphrase)
#
# # Encrypt the public key
# encrypted_public_key = encrypt_key(public_key, passphrase)
#
# # Print the encrypted private key
# print("\nEncrypted Private Key:")
# print(encrypted_private_key)
#
# # Print the encrypted public key
# print("\nEncrypted Public Key:")
# print(encrypted_public_key)
#
#
#
# # Decrypt the private key
# decrypted_private_key = decrypt_key(encrypted_private_key_read, passphrase)
#
# # Decrypt the public key
# decrypted_public_key = decrypt_key(encrypted_public_key_read, passphrase)
#
# # Print the decrypted private key
# print("Private Key before encryption:")
# print(TheRSA.SerializePrivKey(private_key).decode())
#
#     # Print the public key before encryption
# print("\nPublic Key before encryption:")
# print(TheRSA.SerializePublicKey(public_key).decode())