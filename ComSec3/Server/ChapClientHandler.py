import logging
import socketserver

from Auth.Authenticator import Authenticator
from Auth.Confirmation import Confirmation
from Auth.Request import Request
from Auth.Response import Response

logger = logging.getLogger(__name__)

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
            logger.error("Failure in the communications: %s", msg)

    def send_challenge(self):
        ret_val = False
        challenge = Authenticator.generate_challenge(self.authenticator, self.name)
        self.chap_challenge = challenge
        packet = challenge.to_packet()
        try:
            self.request.send(packet)
            ret_val = True
        except IOError as msg:
            logger.error("Error sending challenge: %s", msg)
        return ret_val

    def wait_request(self):
        ret_val = False
        try:
            msg_type = int.from_bytes(self.request.recv(1), byteorder='big')
            if msg_type == Authenticator.REQUEST_TYPE:
                msg_id = int.from_bytes(self.request.recv(1), byteorder='big')
                msg_length = int.from_bytes(self.request.recv(2), byteorder='big')
                msg_data = self.request.recv(msg_length - Authenticator.headerLength)
                if msg_id == 0x00:
                    self.chap_request = Request(msg_data)
                    ret_val = True
        except IOError as msg:
            logger.error("Error receiving request: %s", msg)
        return ret_val

    def wait_response(self):
        ret_val = False
        try:
            msg_type = int.from_bytes(self.request.recv(1), byteorder='big')
            if msg_type == Authenticator.RESPONSE_TYPE:
                msg_id = int.from_bytes(self.request.recv(1), byteorder='big')
                msg_length = int.from_bytes(self.request.recv(2), byteorder='big')
                msg_data = self.request.recv(msg_length - Authenticator.headerLength)
                self.chap_response = Response(msg_id, msg_data, self.name)
                ret_val = True
        except IOError as msg:
            logger.error("Error receiving the response: %s", msg)
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
            logger.error("Error sending success message: %s", msg)
        return ret_val

    def send_failure(self):
        ret_val = False
        self.chap_confirmation = Confirmation(self.chap_challenge.identifier, "Auth error", Confirmation.TYPE_FAILURE)
        packet = self.chap_confirmation.to_packet()
        try:
            self.request.sendall(packet)
            ret_val = True
        except IOError as msg:
            logger.error("Error sending auth failure message: %s", msg)
        return ret_val
