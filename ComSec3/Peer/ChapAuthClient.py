import socket
import struct

from Authenticator.Authenticator import Authenticator
from Authenticator.Challenge import Challenge
from Authenticator.Confirmation import Confirmation
from Authenticator.Request import Request


class ChapAuthClient:
    server_address = None
    server_port = None
    server_socket = None
    # TO-DO: Get name from parameter or Server Class
    server_name = "Server"
    authenticator = None
    chap_request = None
    chap_challenge = None
    chap_response = None
    chap_confirmation = None

    def __init__(self, server, port, secret):
        self.identity = "Server"
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
        ret_val = False
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
        self.chap_request = Request(self.identity)
        packet = self.chap_request.to_packet()
        try:
            self.server_socket.sendall(packet)
            ret_val = True
        except IOError as msg:
            print("Error sending the request", msg)
        return ret_val

    def wait_challenge(self):
        ret_val = False
        try:
            msg_type = self.server_socket.recv(1)
            if msg_type == Authenticator.CHALLENGE_TYPE:
                msg_id = self.server_socket.recv(1)
                msg_length = self.server_socket.recv(2)
                msg_data = self.server_socket.recv(msg_length)
                # TO-DO: Create Challenge Factory like?
                (data_length, values) = struct.unpack('!Bs', msg_data)
                self.chap_challenge = Challenge(msg_id, values[:data_length], values[data_length:])
                ret_val = True
        except IOError as msg:
            print("Error receiving the challenge", msg)
        return ret_val

    def send_response(self):
        ret_val = False
        self.chap_response = self.authenticator.generate_response(self.chap_challenge, self.server_name)
        packet = self.chap_response.to_packet()
        try:
            self.server_socket.sendall(packet)
            ret_val = True
        except IOError as msg:
            print("Error sending the response", msg)
        return ret_val

    def wait_confirmation(self):
        ret_val = False
        try:
            msg_type = self.server_socket.recv(1)
            if msg_type == Authenticator.SUCCESS_TYPE or type == Authenticator.FAILURE_TYPE:
                msg_id = self.server_socket.recv(1)
                msg_length = self.server_socket.recv(2)
                msg_data = self.server_socket.recv(msg_length)
                print("Confirmation message received from server: ", msg_data)
                if type == Authenticator.SUCCESS_TYPE:
                    self.chap_confirmation = Confirmation(msg_id, msg_data, Confirmation.TYPE_SUCCESS)
                    ret_val = True
                else:
                    self.chap_confirmation = Confirmation(msg_id, msg_data, Confirmation.TYPE_FAILURE)
        except IOError as msg:
            print("Error receiving the confirmation", msg)
        return ret_val
