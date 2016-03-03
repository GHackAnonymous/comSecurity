import struct

from .Authenticator import Authenticator


class Request:
    identity = None

    def __init__(self, identity):
        self.identity = identity

    def to_packet(self):
        packet_format = '!BHHs'
        packet_length = Authenticator.HEADER_LENGTH + len(self.identity)
        packet = struct.pack(packet_format, Authenticator.REQUEST_TYPE, packet_length, self.identity)
        return packet
