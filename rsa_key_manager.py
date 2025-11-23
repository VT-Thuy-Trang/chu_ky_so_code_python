from Crypto.PublicKey import RSA

class RSAKeyManager:

    def generate_keypair(bits=2048):
        return RSA.generate(bits)


    def export_private_key(key):
        return key.export_key()


    def export_public_key(key):
        return key.publickey().export_key()


    def save_key_to_file(key_data, filename):
        with open(filename, "wb") as f:
            f.write(key_data)


    def load_key_from_file(filename):
        with open(filename, "rb") as f:
            data = f.read()
        return RSA.import_key(data)