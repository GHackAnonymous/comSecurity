import struct

from Authenticator import Authenticator


class Response:
    VALUE_SIZE_LENGTH = 1
    identifier = None
    data = None
    name = None

    def __init__(self, identifier, data, name):
        self.identifier = identifier
        self.data = data
        self.name = name

    def to_packet(self):
        packet_format = '!BBHBss'
        data_length = len(self.data)
        packet_length = Authenticator.HEADER_LENGTH + self.VALUE_SIZE_LENGTH + len(self.data) + len(self.name)
        packet = struct.pack(packet_format, Authenticator.RESPONSE_TYPE, packet_length, data_length, self.data,
                             self.name)
        return packet
