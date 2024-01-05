import sys
import threading

from source.client.tls_client import TLSConnectClient


class ChatUser(TLSConnectClient):
    def enter_chat(self) -> None:
        self.tls_handshake()

        threading.Thread(target=self.handle_incoming_messages).start()
        threading.Thread(target=self.handle_send_messages).start()

    def handle_incoming_messages(self) -> None:
        while True:
            try:
                encrypted_message = self.communication_socket.recv(1024)
                if not encrypted_message:
                    continue

                decrypted_message = self.decrypt_message(encrypted_message, self.config["master_secret"])
                print(decrypted_message)
            except Exception as e:
                self._logger.error(f"Error handling incoming messages: {e}")
                break

    def handle_send_messages(self) -> None:
        if self.config.get("username") is None:
            self.config["username"] = input("Enter your username: ")
            self._send_encrypted_message(self.config["username"])

        while True:
            try:
                message = input()
                sys.stdout.write("\033[F")  # Move the cursor up one line
                sys.stdout.write("\033[K")  # Clear the line

                print(f"{self.config['username']} >> {message.split(':')[-1]}")

                self._send_encrypted_message(message)
            except Exception as e:
                self._logger.error(f"Error sending message: {e}")
                break
