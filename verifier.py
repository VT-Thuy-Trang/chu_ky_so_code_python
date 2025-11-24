from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# lớp Verifier để xác minh chữ ký bằng khóa công khai RSA
class Verifier:
    # khởi tạo với khóa công khai
    def __init__(self, public_key):
        self.public_key = public_key


    # xác minh chữ ký của dữ liệu
    def verify(self, data: bytes, signature: bytes): # trả về True nếu hợp lệ, False nếu không hợp lệ
        h = SHA256.new(data)
        #xác minh chữ ký
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False