from Server.ChapAuthServer import ChapAuthServer


def main():
    auth_server = ChapAuthServer("127.0.0.1", 60000)
    auth_server.init_server()

if __name__ == "__main__":
    main()
