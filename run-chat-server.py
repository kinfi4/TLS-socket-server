from source.server.chat import ChatServer


if __name__ == "__main__":
    server = ChatServer("localhost", 4433)
    server.run()
