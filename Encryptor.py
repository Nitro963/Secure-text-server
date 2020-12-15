import os

from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.PublicKey import RSA


class SymmetricEncryptor:

    def __init__(self, session_key):
        self.session_key = session_key

    @staticmethod
    def generate_iv():
        return Random.new().read(AES.block_size)

    def encrypt(self, data: bytes, iv):
        try:
            cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(data, AES.block_size))
            return ciphertext
        except ValueError:
            print('please specify iv')

    def decrypt(self, data: bytes, iv):
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted_data

    @staticmethod
    def generate_key():
        return Random.get_random_bytes(AES.block_size)


class AsymmetricEncryptor:

    @staticmethod
    def generate_key_pairs():
        key = RSA.generate(2048)

        private_key = key.export_key()

        public_key = key.publickey().export_key()

        return public_key, private_key

    @staticmethod
    def read_key_pairs(key_pairs: Tuple[str, str]):
        if os.path.exists(key_pairs[0]) and os.path.exists(key_pairs[1]):
            public_key = RSA.import_key(open(key_pairs[0]).read())

            private_key = RSA.import_key(open(key_pairs[1]).read())

            return public_key, private_key

        public_key, private_key = AsymmetricEncryptor.generate_key_pairs()

        with open(key_pairs[0], 'wb') as f:
            f.write(public_key)

        with open(key_pairs[1], 'wb') as f:
            f.write(private_key)

        return RSA.import_key(public_key), RSA.import_key(private_key)

    @staticmethod
    def encrypt(public_key: RsaKey, data: bytes):
        return PKCS1_OAEP.new(public_key).encrypt(data)

    @staticmethod
    def decrypt(private_key: RsaKey, data: bytes):
        return PKCS1_OAEP.new(private_key).decrypt(data)
