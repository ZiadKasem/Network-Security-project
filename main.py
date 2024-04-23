from AESDES import *
from RSA import *
from Crypto.Random import get_random_bytes



if __name__ == '__main__':
    # symmetric key for main communication (block cipher encrypted)
    symmetric_key = get_random_bytes(16)
    print(f"This is the symmetric key: {symmetric_key} before encryption")

    RSAEncryption = RSA()
    # asymmetric keys created for securely sharing symmetric key
    user1_public_key, user1_private_key = RSAEncryption.GenerateCommunicationKeys()
    user2_public_key, user2_private_key = RSAEncryption.GenerateCommunicationKeys()

    # encryption of symmetric key (user1 shares symmetric key with user2)
    encrypted_symmetric_key = RSAEncryption.RSAEncrypt(symmetric_key, RSAEncryption.SerializePublicKey(user2_public_key))
    print("Encrypted with Public:", encrypted_symmetric_key)

    # decryption of symmetric key (user2 decrypts the encrypted shared symmetric key sent from user1)
    decrypted_symmetric_key = RSAEncryption.RSADecrypt(encrypted_symmetric_key,RSAEncryption.SerializePrivKey(user2_private_key))
    print("Decrypted with Public:", decrypted_symmetric_key)

    print("\n")
    # plaintext message to be sent
    message = b"Hello user2"

    # using AES block encryption to encrypt the data
    MyBlockCipher = BlockCipher()
    ciphertext, tag, nonce = MyBlockCipher.encrypt_AES_EAX(message, decrypted_symmetric_key)
    print("AES EAX Ciphertext:", ciphertext)

    # using AES block decryption to encrypt the data
    plaintext = MyBlockCipher.decrypt_AES_EAX(ciphertext, decrypted_symmetric_key, nonce, tag)
    print("AES EAX Plaintext:", plaintext)

