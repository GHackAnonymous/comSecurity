import socket
from Authenticator.Authenticator import Authenticator
from Authenticator.Challenge import Challenge


class ChapAuthClient:
    server_address = None
    server_port = None
    server_socket = None
    authenticator = None
    challenge = None
    response = None

    def __init__(self, server, port, secret):
        self.server_address = server
        self.server_port = port
        self.authenticator = Authenticator(secret)

    def connect(self):
        ret_val = False
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            server_socket.connect((self.server_address, self.server_port,))
            ret_val = True
        except OSError as msg:
            print("Error creating socket", msg)
        return ret_val

    def authenticate(self):
        request_ok = self.send_request()
        if request_ok is True:
            challenge_ok = self.wait_challenge()
            if challenge_ok is True:
                response_ok = self.send_response()
                if response_ok is True:
                    ret_val = self.wait_confirmation()
        return ret_val

    def disconnect(self):
        self.server_socket.shutdown()
        self.server_socket.close()

    def send_request(self):
        ret_val = False
        try:
            packet = self.authenticator.generate_packet(Authenticator.REQUEST_TYPE, 0x00, self.server_address)
            self.server_socket.sendall(packet)
            ret_val = True
        except IOError as msg:
            print("Error sending the request", msg)
        return ret_val

    def wait_challenge(self):
        ret_val = False
        try:
            type = self.server_socket.recv(1)
            if type == 0x01:
                id = self.server_socket.recv(1)
                length = self.server_socket.recv(2)
                data = self.server_socket.recv(length)
                self.challenge = Challenge(id, data)
                ret_val = True
        except IOError as msg:
            print("Error receiving the challenge", msg)
        return ret_val

    def send_response(self):
        ret_val = False
        self.response = self.authenticator.generate_response(self.challenge)
        packet = self.authenticator.generate_packet(Authenticator.RESPONSE_TYPE, self.response.identifier, self.response.response_hash)
        try:
            self.server_socket.sendall(packet)
            ret_val = True
        except IOError as msg:
            print("Error sending the response", msg)
        return ret_val

    def wait_confirmation(self):
        ret_val = False
        try:
            type = self.server_socket.recv(1)
            if type == Authenticator.SUCCESS_TYPE or type == Authenticator.FAILURE_TYPE:
                id = self.server_socket.recv(1)
                length = self.server_socket.recv(2)
                data = self.server_socket.recv(length)
                print("Confirmation message received from server: ", data)
            if type == Authenticator.SUCCESS_TYPE:
                ret_val = True
        except IOError as msg:
            print("Error receiving the confirmation", msg)
        return ret_val
