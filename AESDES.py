from Crypto.Cipher import AES , DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

class BlockCipher:
    def __init__(self):
        pass
    def encrypt_AES_EAX(self,data, key):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, tag , cipher.nonce

    def decrypt_AES_EAX(self,ciphertext, key, nonce, tag):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    def encrypt_DES(self,data, key):
        iv = get_random_bytes(8)  # Generate an initialization vector (IV)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_data = pad(data, DES.block_size)
        ciphertext = iv + cipher.encrypt(padded_data)
        return ciphertext

    def decrypt_DES(self,ciphertext, key):
        iv = ciphertext[:8]  # Extract the IV from the ciphertext
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[8:])
        return plaintext

