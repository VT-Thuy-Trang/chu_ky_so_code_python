from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class Verifier:
    def __init__(self, public_key):
        self.public_key = public_key

    def verify(self, data: bytes, signature: bytes):
        h = SHA256.new(data)
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False