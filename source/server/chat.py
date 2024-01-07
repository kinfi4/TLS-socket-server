import socket

from source.server.tls_server import TLSServer


class ChatServer(TLSServer):
    def handle_decrypted_message(self, session_id: bytes, client_socket: socket.socket, decrypted_message: str) -> None:
        if self.sessions[session_id].get("username") is None:
            self.sessions[session_id]["username"] = decrypted_message
            self._logger.info(f"User {decrypted_message} connected")
            return

        if decrypted_message == "CLOSE":
            self._logger.info(f"User {self.sessions[session_id]['username']} disconnected")
            client_socket.close()
            del self.sessions[session_id]
            return

        self._handle_chat_message(session_id, decrypted_message)

    def _handle_chat_message(self, session_id: bytes, decrypted_message: str) -> None:
        if not self._validate_message(decrypted_message):
            self._send_encrypted_message(session_id, "SERVER ERROR: Invalid message format")
            return

        recipient_username, *message = decrypted_message.split(":")
        message = ":".join(message)

        self._logger.info(f"Sending message from {self.sessions[session_id]['username']}: to {recipient_username}")

        recipient_session_id = self._find_message_recipient_session_id(recipient_username)

        if recipient_session_id is None:
            self._send_encrypted_message(session_id, "SERVER ERROR: User not found")
            return
        if recipient_session_id == session_id:
            self._send_encrypted_message(session_id, "SERVER ERROR: Cannot send message to self")
            return

        self._send_encrypted_message(recipient_session_id, f"{self.sessions[session_id]['username']} >> {message}")

    def _find_message_recipient_session_id(self, recipient_username: str) -> bytes | None:
        for session_id, session_data in self.sessions.items():
            if session_data.get("username") == recipient_username:
                return session_id

        return None

    def _validate_message(self, message: str) -> bool:
        return ":" in message
