import socketserver

from Authenticator.Authenticator import Authenticator
from Authenticator.Confirmation import Confirmation
from Authenticator.Request import Request


class ChapClientHandler(socketserver.BaseRequestHandler):
    chap_request = None
    chap_challenge = None
    chap_response = None
    chap_confirmation = None
    authenticator = Authenticator("Secret")
    name = "Server"

    def handle(self):
        try:
            request_ok = self.wait_request()
            if request_ok is True:
                self.send_challenge()
                response_ok = self.wait_response()
                if response_ok is True:
                    challenge_ok = self.authenticator.check_response(self.chap_challenge, self.chap_response)
                    if challenge_ok is True:
                        self.send_success()
                    else:
                        self.send_failure()
        except IOError as msg:
            print("Failure in the communications: ", msg)
        finally:
            self.finish()

    def send_challenge(self):
        ret_val = False
        challenge = Authenticator.generate_challenge(self.authenticator, self.name)
        self.chap_challenge = challenge
        packet = challenge.to_packet()
        try:
            self.request.send(packet)
            ret_val = True
        except IOError as msg:
            print("Error sending challenge: ", msg)
        return ret_val

    def wait_request(self):
        ret_val = False
        try:
            msg_type = self.request.recv(1)
            if msg_type == 0:
                msg_id = self.request.recv(1)
                msg_length = self.request.recv(2)
                msg_data = self.request.recv(msg_length - Authenticator.headerLength)
                if msg_id == 0:
                    self.chap_request = Request(msg_data)
                    ret_val = True
        except IOError as msg:
            print("Error receiving request: ", msg)
        return ret_val

    def wait_response(self):
        ret_val = False
        try:
            msg_type = self.request.recv(1)
            if msg_type == 2:
                msg_id = self.request.recv(1)
                msg_length = self.request.recv(2)
                msg_data = self.request.recv(msg_length - Authenticator.headerLength)
                self.chap_response = Response.Response(msg_id, msg_data, self.name)
                ret_val = True
        except IOError as msg:
            print("Error receiving the response: ", msg)
        return ret_val

    def send_success(self):
        ret_val = False
        self.chap_confirmation = Confirmation(self.chap_challenge.identifier, "Correctly authenticated",
                                              Confirmation.TYPE_SUCCESS)
        packet = self.chap_confirmation.to_packet()
        try:
            self.request.sendall(packet)
            ret_val = True
        except IOError as msg:
            print("Error sending success message: ", msg)
        return ret_val

    def send_failure(self):
        ret_val = False
        self.chap_confirmation = Confirmation(self.chap_challenge.identifier, "Auth error", Confirmation.TYPE_FAILURE)
        packet = self.chap_confirmation.to_packet()
        try:
            self.request.sendall(packet)
            ret_val = True
        except IOError as msg:
            print("Error sending auth failure message: ", msg)
        return ret_val
