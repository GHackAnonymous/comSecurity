import struct

from Auth.Authenticator import *


class Confirmation:
    TYPE_FAILURE = False
    TYPE_SUCCESS = True

    identifier = None
    message = None
    success = False

    def __init__(self, identifier, message, success):
        self.identifier = identifier
        self.message = message
        self.success = success

    def to_packet(self):
        packet_length = Authenticator.HEADER_LENGTH + len(self.message)
        packet_format = '!BBH' + str(packet_length) + 's'
        if self.success is True:
            packet_type = Authenticator.SUCCESS_TYPE
        else:
            packet_type = Authenticator.FAILURE_TYPE
        packet = struct.pack(packet_format
                             , packet_type
                             , packet_length
                             , self.message.encode('utf-8'))
        return packet
