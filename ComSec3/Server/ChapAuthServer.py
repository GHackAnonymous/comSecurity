import logging
import socketserver
import threading

from Server.ChapClientHandler import ChapClientHandler

logger = logging.getLogger(__name__)


class ChapAuthServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    host = None
    port = None
    server = None
    isActive = False

    def __init__(self, host, port):
        self.host = host
        self.port = port
        super()

    def init_server(self):
        self.server = socketserver.ThreadingTCPServer((self.host, self.port), ChapClientHandler, True)
        logger.info("Server started")
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

    def stop_server(self):
        self.server.shutdown()
