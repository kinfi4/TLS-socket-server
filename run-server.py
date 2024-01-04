from source.server import TLSServer


if __name__ == "__main__":
    server = TLSServer("localhost", 4433)
    server.run()
