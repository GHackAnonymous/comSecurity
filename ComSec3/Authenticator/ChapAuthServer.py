import socket
import socketserver
import threading
from Authenticator.ChapClientHandler import handleClient



def parse_message(message):
    type = message[0]
    id = message[1]
    length = message[2:3]
    data = message[4:length]
    return {type, id, length, data}



class ChapAuthServer():

    host = None
    port = None
    serverSocker = None
    isActive = False

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def initServer:
        serverSocket = socketserver.ThreadingTCPServer("localhost", handleClient, True)


