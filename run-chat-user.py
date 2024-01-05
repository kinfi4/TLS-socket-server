from source.client.chat_user import ChatUser


if __name__ == "__main__":
    client = ChatUser("localhost", 4433)
    client.enter_chat()
