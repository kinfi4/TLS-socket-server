from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESDecryptorMixin:
    def decrypt_message(self, message: bytes, master_secret: bytes) -> str:
        iv = message[:16]
        encrypted_message = message[16:]

        cipher = Cipher(algorithms.AES(master_secret), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

        return decrypted_message.decode("utf-8")
