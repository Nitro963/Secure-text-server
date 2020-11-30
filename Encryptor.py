from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.PublicKey import RSA


class Encryptor:
    key = b'abcd1234efgh5678'

    def __init__(self, key_pairs: Tuple[str, str]):
        self.public_key = RSA.import_key(open(key_pairs[0]).read())
        self.private_key = RSA.import_key(open(key_pairs[1]).read())
        self.session_key = None

    @staticmethod
    def generate_iv():
        return Random.new().read(AES.block_size)

    def encrypt_message(self, message: bytes, iv):
        try:
            cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(message, AES.block_size))
            return ciphertext
        except ValueError:
            print('please specify iv')

    def decrypt_message(self, data: bytes, iv):
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted_data

    @staticmethod
    def generate_key_pairs():
        key = RSA.generate(2048)
        private_key = key.export_key()

        public_key = key.publickey().export_key()

        return private_key, public_key

    @staticmethod
    def generate_session_key():
        return Random.get_random_bytes(AES.block_size)

    def decrypt_session_key(self, encrypted_session_key):
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        self.session_key = cipher_rsa.decrypt(encrypted_session_key)

    @staticmethod
    def encrypt(public_key: RsaKey, data: bytes):
        return PKCS1_OAEP.new(public_key).encrypt(data)
