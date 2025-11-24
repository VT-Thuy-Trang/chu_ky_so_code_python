from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# lớp Signer để ký dữ liệu bằng khóa riêng RSA
class Signer:
    # khởi tạo với khóa riêng
    def __init__(self, private_key):
        self.private_key = private_key

    # ký dữ liệu và trả về chữ ký
    def sign(self, data: bytes):
        h = SHA256.new(data)
        return pkcs1_15.new(self.private_key).sign(h)

    # tạo hàm băm SHA-256 và trả về giá trị băm ở dạng thập lục phân
    @staticmethod
    def digest_hex(data: bytes):
        return SHA256.new(data).hexdigest()