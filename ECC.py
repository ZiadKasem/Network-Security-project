from tinyec import registry
import secrets

class ECC:
    def __init__(self):
        self.curve = registry.get_curve('brainpoolP256r1')
        pass
    def compress(self,pubKey):
        return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

    def generateKeys(self):

        user1PrivKey = secrets.randbelow(self.curve.field.n)
        user1PubKey = user1PrivKey * self.curve.g
        print("User 1 public key:", self.compress(user1PubKey))

        user2PrivKey = secrets.randbelow(self.curve.field.n)
        user2PubKey = user2PrivKey * self.curve.g
        print("Bob public key:", self.compress(user2PubKey))

        print("Now exchange the public keys (e.g. through Internet)")

        user1SharedKey = user1PrivKey * user2PubKey
        print("Alice shared key:", self.compress(user1SharedKey))

        user2SharedKey = user2PrivKey * user1PubKey
        print("Bob shared key:", self.compress(user2SharedKey))

        print("Equal shared keys:", user1SharedKey == user2SharedKey)
        return user1PrivKey,user1PubKey,user1SharedKey, user2PrivKey, user2PubKey, user2SharedKey