from Peer.ChapAuthClient import ChapAuthClient


def main():
    auth_client = ChapAuthClient("127.0.0.1", 60000, "secret")
    auth_client.connect()
    auth_result = auth_client.authenticate()
    if auth_result is True:
        print("Client successfully authenticated")
    else:
        print("Client not authenticated")

if __name__ == "__main__":
    main()
