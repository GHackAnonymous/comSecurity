import socket
import struct
import threading
import socketserver
from Authenticator.Authenticator import *


class ChapClientHandler(socketserver.BaseRequestHandler):
    chapChallenge = None
    chapResponse = None
    authenticator = Authenticator("Secret")

    def handle(self):
        try:
            requestOk = self.wait_request()
            if requestOk is True:
                self.send_challenge()
                responseOK = self.wait_response()
                if responseOK is True:
                    challengeOK = Authenticator.check_response(self.chapChallenge, self.chapResponse)
                    if challengeOK is True:
                        self.send_confirmation()
                    else:
                        self.send_failure()
        except IOError:
            print("Failure in the communications")
        finally:
            self.finish()

    def send_challenge(self):
        challenge = Authenticator.generate_challenge(self.authenticator)
        self.chapChallenge = challenge
        packet = Authenticator.generate_packet(self.authenticator, 1, challenge.identifier, challenge.value)
        self.request.send(packet)

    def wait_request(self):
        type = self.request.recv(1)
        if type == 0:
            id = self.request.recv(1)
            length = self.request.recv(2)
            data = self.request.recv(length - Authenticator.headerLength)
            return True
        else:
            return False

    def wait_response(self):
        type = self.request.recv(1)
        if type == 2:
            id = self.request.recv(1)
            length = self.request.recv(2)
            data = self.request.recv(length - Authenticator.headerLength)
            self.chapResponse = Response.Response(id, data)
            return True
        else:
            return False

    def send_confirmation(self):
        packet = Authenticator.generate_packet(self.authenticator, 3, self.chapResponse.identifier,
                                               "Correctly Authenticated")
        self.request.sendall(packet)

    def send_failure(self):
        packet = Authenticator.generate_packet(self.authenticator, 3, self.chapResponse.identifier,
                                               "Authentication Error")
        self.request.sendall(packet)
