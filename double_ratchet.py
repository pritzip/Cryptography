# requires to install cryptography library and latest python [pip install cryptography]
#--------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------#
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#--------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------#
class SymmetricRatchet:
    def __init__(self, key):
        self.key = key
        self.counter = 0
#--------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------#
    def next(self):
        self.counter += 1
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=str(self.counter).encode(),
        ).derive(self.key)
#--------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------#
class DoubleRatchet:
    def __init__(self, shared_secret):
        self.root_ratchet = SymmetricRatchet(shared_secret)
        self.DHratchet = X25519PrivateKey.generate()
        self.refresh_ratchet()
#--------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------#
    def refresh_ratchet(self):
        dh_send = self.DHratchet.exchange(self.DHratchet.public_key())
        shared_send = self.root_ratchet.next()
        self.send_ratchet = SymmetricRatchet(shared_send)
#--------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------#
    def ratchet_and_encrypt(self, plaintext):
        self.refresh_ratchet()
        key = self.send_ratchet.next()
        return AESGCM(key).encrypt(nonce=b'\x00'*12, data=plaintext, associated_data=None)
#--------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------#
    def decrypt(self, ciphertext, pbkey):
        dh_recv = X25519PrivateKey.from_public_bytes(pbkey).exchange(self.DHratchet.public_key())
        shared_recv = self.root_ratchet.next()
        recv_ratchet = SymmetricRatchet(shared_recv)
        key = recv_ratchet.next()
        return AESGCM(key).decrypt(nonce=b'\x00'*12, data=ciphertext, associated_data=None)


#--------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------#

# Create a shared secret (this should be a secure random value in a real application)
shared_secret = b'secure_random_value'

# Create a DoubleRatchet instance
ratchet = DoubleRatchet(shared_secret)

# Encrypt a message
ciphertext = ratchet.ratchet_and_encrypt(b'Hello, world!')

# Decrypt the message
# For this, you'd normally use the recipient's public key, which isn't available in this example
# pbkey = recipient_public_key
# plaintext = ratchet.decrypt(ciphertext, pbkey)
