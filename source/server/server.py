import os
import json
import base64
import socket
import logging
import threading

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from source.common import AESDecryptorMixin, AESEncryptorMixin


class TLSServer(AESDecryptorMixin, AESEncryptorMixin):
    sessions_lock = threading.RLock()

    def __init__(
        self,
        host: str,
        port: int,
        timeout__seconds: int = 60*60,
    ) -> None:
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sessions = {}

        self._timeout__seconds = timeout__seconds

        self._logger = logging.getLogger(__name__)

        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self._public_key = self._private_key.public_key()

    def run(self) -> None:
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self._logger.info(f"Server listening on {self.host}:{self.port}")

        try:
            while True:
                client_socket, addr = self.server_socket.accept()

                session_id = os.urandom(16)
                self._start_new_session(session_id, addr, client_socket)

                threading.Thread(target=self.handle_client, args=(session_id,)).start()
        finally:
            self.server_socket.close()

    def handle_client(self, session_id: bytes) -> None:
        client_socket: socket.socket = self.sessions[session_id]["socket"]

        try:
            self.handshake(session_id, client_socket)
            self.handle_secure_data(session_id, client_socket)
        except Exception as e:
            self._logger.error(f"Error handling client {session_id}: {e}")
        finally:
            if client_socket.fileno() != -1:  # if socket is not closed
                client_socket.close()

            del self.sessions[session_id]

    def handshake(self, session_id: bytes, client_socket: socket.socket) -> None:
        # TODO: implement TLS versioning and cipher suite negotiation
        self._receive_client_hello(session_id, client_socket)

        self._perform_server_hello(session_id, client_socket)

        self._receive_pre_master_secret(session_id, client_socket)

        self._make_master_secret(session_id)

        self._send_encryption_complete(session_id, client_socket)
        self._validate_encryption_complete_from_client(session_id, client_socket)

        self._logger.info(f"Handshake with {self.sessions[session_id]['address']} complete")

    def handle_secure_data(self, session_id: bytes, client_socket: socket.socket) -> None:
        pass

    def _send_encryption_complete(self, session_id: bytes, client_socket: socket.socket) -> None:
        message = "COMPLETE"
        encrypted_message = self.encrypt_message(message, self.sessions[session_id]["master_secret"])

        client_socket.send(encrypted_message)

    def _validate_encryption_complete_from_client(self, session_id: bytes, client_socket: socket.socket) -> None:
        client_complete_message = client_socket.recv(1024)

        decrypted_message = self.decrypt_message(client_complete_message, self.sessions[session_id]["master_secret"])

        if decrypted_message != "COMPLETE":
            raise ValueError("Client did not send correct COMPLETE message")

    def _make_master_secret(self, session_id: bytes) -> None:
        """
        Derives the master secret from the pre-master secret and the client and server randoms.
        """

        with self.sessions_lock:
            session = self.sessions[session_id]

            if session["premaster_secret"] is None or session["server_random"] is None or session["client_random"] is None:
                raise ValueError("Cannot make master secret without secret, server random, and client random")

            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(session["premaster_secret"])
            digest.update(session["client_random"])
            digest.update(session["server_random"])
            master_key = digest.finalize()

            self._logger.debug("The master secret is: " + str(master_key))

            self._update_session(session_id, master_secret=master_key)

    def _receive_client_hello(self, session_id: bytes, client_socket: socket.socket) -> None:
        """
        Receives the ClientHello message from the client and parses it.
        The ClientHello message format is assumed to be a JSON string containing
        'tls_version', 'cipher_suites', and 'client_random'.
        """

        try:
            client_hello_data = client_socket.recv(1024).decode("utf-8")
            client_hello = json.loads(client_hello_data)

            tls_version = client_hello["tls_version"]
            cipher_suites = client_hello["cipher_suite"]
            client_random_string = client_hello["client_random"]
            client_random = base64.b64decode(client_random_string)

            self._logger.debug(f"Received client hello: {client_hello_data}")

            self._update_session(session_id, client_random=client_random)
        except json.JSONDecodeError:
            raise ValueError("Invalid ClientHello format")
        except KeyError:
            raise ValueError("Missing fields in ClientHello")
        except socket.error as e:
            raise ConnectionError(f"Socket error during ClientHello reception: {e}")

    def _perform_server_hello(self, session_id: bytes, client_socket: socket.socket) -> None:
        """
        Sends the ServerHello message to the client.
        The ServerHello message format is assumed to be a JSON string containing
        'tls_version', 'cipher_suite', and 'server_random'.
        """

        server_random = os.urandom(16)
        server_hello = json.dumps({
            "tls_version": "1.2",
            "cipher_suite": "TLS_RSA_WITH_AES_256_CBC_SHA",
            "server_random": base64.b64encode(server_random).decode("ascii"),
            "server_public_key": base64.b64encode(
                self._public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).decode("ascii")
        })

        self._update_session(session_id, server_random=server_random)
        client_socket.send(server_hello.encode("utf-8"))

    def _receive_pre_master_secret(self, session_id: bytes, client_socket: socket.socket) -> None:
        """
        Receives the PreMasterSecret message from the client and parses it.
        The PreMasterSecret message format is assumed to be a JSON string containing
        'encrypted_pre_master_secret'.
        """

        try:
            encrypted_pre_master_secret = client_socket.recv(1024).decode("utf-8")
            encrypted_pre_master_secret = json.loads(encrypted_pre_master_secret)["encrypted_pre_master_secret"]
        except json.JSONDecodeError:
            raise ValueError("Invalid PreMasterSecret format")
        except KeyError:
            raise ValueError("Missing fields in PreMasterSecret")
        except socket.error as e:
            raise ConnectionError(f"Socket error during PreMasterSecret reception: {e}")

        pre_master_secret = self._private_key.decrypt(
            base64.b64decode(encrypted_pre_master_secret),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )

        self._logger.debug("The pre-master secret is: " + str(pre_master_secret))

        self._update_session(session_id, premaster_secret=pre_master_secret)

    def _start_new_session(self, session_id: bytes, address: str, client_socket: socket.socket) -> None:
        with self.sessions_lock:
            if session_id in self.sessions:  # that's nearly impossible, but just in case
                self.sessions[session_id]["socket"].close()
                del self.sessions[session_id]

            self.sessions[session_id] = {
                "address": address,
                "socket": client_socket,
                "premaster_secret": None,
                "server_random": None,
                "client_random": None,
                "master_secret": None,
            }

    def _update_session(self, session_id: bytes, **kwargs) -> None:
        with self.sessions_lock:
            self.sessions[session_id].update(kwargs)
