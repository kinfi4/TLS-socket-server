from source.client import TLSConnectClient


if __name__ == "__main__":
    client = TLSConnectClient("localhost", 4433)
    client.tls_handshake()
    client.send_test_messages()
