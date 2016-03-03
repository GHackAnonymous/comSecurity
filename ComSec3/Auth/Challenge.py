import struct

from Auth.Authenticator import *


class Challenge:
    VALUE_SIZE_LENGTH = 1

    identifier = None
    data = None
    name = None

    def __init__(self, identifier, data, name):
        self.identifier = identifier
        self.data = data
        self.name = name

    def to_packet(self):
        data_length = len(self.data)
        name_length = len(self.name)
        packet_length = Authenticator.HEADER_LENGTH + self.VALUE_SIZE_LENGTH + data_length + name_length
        packet_format = '!BBHB' + str(data_length) + 's' + str(name_length) + 's'
        packet = struct.pack(packet_format
                             , Authenticator.CHALLENGE_TYPE
                             , packet_length
                             , data_length
                             , self.data.encode('utf-8')
                             , self.name.encode('utf-8'))
        return packet
