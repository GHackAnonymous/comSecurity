from Server.ChapClientHandler import *


class ChapAuthServer:
    host = None
    port = None
    server = None
    isActive = False

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def init_server(self):
        server = socketserver.ThreadingTCPServer((self.host, self.port,), ChapClientHandler.handle, True)
        server.serve_forever()
