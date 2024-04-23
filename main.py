import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def GenerateCommunicationKeys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return public_key,private_key

def SerializePublicKey(publicKey):
    publicKeyPemSerialized = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return publicKeyPemSerialized

def SerializePrivKey(private_key):
    PrivKeyPemSerialized = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return PrivKeyPemSerialized

def RSAEncrypt(plaintext, serializedPublicKey):
    publicKey = serialization.load_pem_public_key(
        serializedPublicKey,
        backend=default_backend()
    )
    ciphertext = publicKey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def RSADecript(ciphertext, serialized_private_key):

    loaded_private_key = serialization.load_pem_private_key(
        serialized_private_key,
        password=None,
        backend=default_backend()
    )

    # Decrypt the data
    decrypted_data = loaded_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_data

def hash_data(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def create_signature(plaintext, serialized_private_key):

    loaded_private_key = serialization.load_pem_private_key(
        serialized_private_key,
        password=None,
        backend=default_backend()
    )

    hashed = hash_data(plaintext)

    signature = loaded_private_key.sign(
        hashed,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(plaintext, signature, serialized_public_key):

    loaded_public_key = serialization.load_pem_public_key(
        serialized_public_key,
        backend=default_backend()
    )

    hashed = hash_data(plaintext)

    try:
        loaded_public_key.verify(
            signature,
            hashed,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # print("Verification Valid!")
        return True
    except:
        # print("Verification Failed")
        return False

if __name__ == '__main__':
    # Example Usage
    public_key, private_key = GenerateCommunicationKeys()
    plaintext = b"Hello, secure email communication!"


    # Hashing (SHA-256)
    hashed_data = hash_data(plaintext)

    # Pub Encrypt
    ciphertext = RSAEncrypt(plaintext, SerializePublicKey(public_key))
    print("Encrypted with Public:", ciphertext)

    # Priv Decription
    DecriptedText = RSADecript(ciphertext, SerializePrivKey(private_key))
    print("Decrypted with Private:", DecriptedText)

    # Digital Signature
    signature = create_signature(plaintext, SerializePrivKey(private_key))
    verify_signature(plaintext, signature, SerializePublicKey(public_key))


    # Base64 Encoding for display
    print("Plaintext:", plaintext.decode())
    print("Hashed Data:", base64.b64encode(hashed_data).decode())
    print("Signature:", base64.b64encode(signature).decode())