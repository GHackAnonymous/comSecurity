import socket
import struct
import threading
import socketserver
from Authenticator.Authenticator import *
class ChapClientHandler(socketserver.BaseRequestHandler):
    challenge = None
    response = None
    headerLength = 4

    def handle(self):
        type = self.request.recv(1)
        if type is 0:
            identifier = self.request.recv(1)
            if identifier is 0:
                self.sendChallenge()
            else:
                print("Incorrect identifier")
        else:
            print("Incorrect message type")

    def sendChallenge(self):
        challenge = Authenticator.generate_challenge()
        packetLength = self.headerLength + len(challenge.value)
        packetFormat = '!BBH' + str(len(challenge.data) + 's')
        packet = struct.pack(packetFormat, 1, challenge.identifier, packetLength, challenge.value)
        self.response.send(packet)