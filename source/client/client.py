import base64
import json
import os
import socket
import logging
from typing import Any

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from source.common import AESDecryptorMixin, AESEncryptorMixin


class TLSConnectClient(AESDecryptorMixin, AESEncryptorMixin):
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

        self.config: dict[str, Any] = {
            "client_random": None,
            "server_random": None,
            "premaster_secret": None,
            "master_secret": None,
            "server_public_key": None,
        }

        self._logger = logging.getLogger(__name__)

    def tls_handshake(self) -> None:
        client_socket = self._connect()
        self._send_client_hello(client_socket)

        self._receive_server_hello(client_socket)

        self._send_pre_master(client_socket)

        self._generate_master_key()

        self._get_handshake_complete_message(client_socket)
        self._send_handshake_complete_message(client_socket)

        self._logger.info(f"Handshake with server complete")

    def _connect(self) -> socket.socket:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))

        return client_socket

    def _send_client_hello(self, client_socket: socket.socket) -> None:
        client_random = os.urandom(16)
        self.config["client_random"] = client_random

        client_random_encoded = base64.b64encode(client_random).decode("ascii")

        tls_hello = {
            "tls_version": "1.2",
            "cipher_suite": "TLS_RSA_WITH_AES_256_CBC_SHA",
            "client_random": client_random_encoded,
        }

        tls_hello_dump = json.dumps(tls_hello)

        self._logger.debug(f"Sending client hello: {tls_hello_dump}")

        client_socket.sendall(tls_hello_dump.encode("utf-8"))

    def _receive_server_hello(self, client_socket: socket.socket) -> None:
        server_hello_data = client_socket.recv(1024).decode("utf-8")
        server_hello = json.loads(server_hello_data)

        self._logger.debug(f"Received server hello: {server_hello_data}")

        server_random_encoded = server_hello["server_random"]
        server_random = base64.b64decode(server_random_encoded)
        self.config["server_random"] = server_random

        server_public_key_encoded = server_hello["server_public_key"]
        server_public_key_bytes = base64.b64decode(server_public_key_encoded)

        public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )
        self.config["server_public_key"] = public_key

    def _send_pre_master(self, client_socket: socket.socket) -> None:
        premaster_bytes = os.urandom(32)
        self.config["premaster_secret"] = premaster_bytes

        public_key: RSAPublicKey = self.config["server_public_key"]
        encrypted_premaster = public_key.encrypt(
            premaster_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )

        encrypted_premaster_encoded = base64.b64encode(encrypted_premaster).decode("ascii")

        payload = json.dumps({
            "encrypted_pre_master_secret": encrypted_premaster_encoded
        }).encode("utf-8")

        client_socket.sendall(payload)

    def _generate_master_key(self) -> None:
        if self.config["premaster_secret"] is None or self.config["server_random"] is None or self.config["client_random"] is None:
            raise ValueError("Cannot make master secret without secret, server random, and client random")

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.config["premaster_secret"])
        digest.update(self.config["client_random"])
        digest.update(self.config["server_random"])
        master_key = digest.finalize()

        self._logger.debug("The master secret is: " + str(master_key))

        self.config["master_secret"] = master_key

    def _get_handshake_complete_message(self, client_socket: socket.socket) -> None:
        server_complete_message = client_socket.recv(1024)
        decrypted_message = self.decrypt_message(server_complete_message, self.config["master_secret"])

        if decrypted_message != "COMPLETE":
            raise ValueError("Client did not send correct COMPLETE message")

    def _send_handshake_complete_message(self, client_socket: socket.socket) -> None:
        message = "COMPLETE"
        encrypted_message = self.encrypt_message(message, self.config["master_secret"])

        client_socket.sendall(encrypted_message)
