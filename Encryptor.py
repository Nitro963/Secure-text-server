from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.PublicKey import RSA


class Encryptor:
    key = b'abcd1234efgh5678'

    def generate_iv(self):
        return Random.new().read(AES.block_size)

    def encrypt_message(self, message: str,iv):
        print('message',message)
    @staticmethod
    def generate_iv():
        return Random.new().read(AES.block_size)

    def encrypt_message(self, message: bytes, iv):
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(message, AES.block_size))
            return ciphertext
        except ValueError:
            print('please specify iv')

    def decrypt_message(self, data: bytearray,iv):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(data), AES.block_size).decode()
        return decrypted_text
    def decrypt_message(self, data: bytes, iv):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted_data

    @staticmethod
    def generate_key_pairs():
        key = RSA.generate(2048)
        private_key = key.export_key()

        public_key = key.publickey().export_key()

        return private_key, public_key
