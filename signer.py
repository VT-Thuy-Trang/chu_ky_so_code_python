from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class Signer:
    def __init__(self, private_key):
        self.private_key = private_key

    def sign(self, data: bytes):
        h = SHA256.new(data)
        return pkcs1_15.new(self.private_key).sign(h)

    @staticmethod
    def digest_hex(data: bytes):
        return SHA256.new(data).hexdigest()