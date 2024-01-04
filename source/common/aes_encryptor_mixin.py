import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class AESEncryptorMixin:
    def encrypt_message(self, message: str, master_secret: bytes) -> bytes:
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(master_secret), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()  # 128-bit block size for AES
        padded_data = padder.update(message.encode("utf-8")) + padder.finalize()

        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        return iv + encrypted_message
