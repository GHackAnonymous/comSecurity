import logging
from Server.ChapAuthServer import ChapAuthServer

def main():
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
    auth_server = ChapAuthServer("127.0.0.1", 60000)
    auth_server.init_server()
    print("Press any key to exit")
    input()
    auth_server.stop_server()

if __name__ == "__main__":
    main()
