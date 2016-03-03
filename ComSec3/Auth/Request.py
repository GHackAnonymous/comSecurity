import struct

from Auth.Authenticator import *


class Request:
    peer_id = 0x00
    identity = None

    def __init__(self, identity):
        self.identity = identity

    def to_packet(self):
        identity_length = len(self.identity)
        packet_format = '!BHH' + str(identity_length) + 's'
        packet_length = Authenticator.HEADER_LENGTH + identity_length
        packet = struct.pack(packet_format
                             , Authenticator.REQUEST_TYPE
                             , self.peer_id
                             , packet_length
                             , self.identity.encode('utf-8'))
        return packet
