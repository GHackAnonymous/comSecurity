import binascii
import struct
class Challenge:
    code = 0x01
    identifier = None
    value = ''

    def __init__(self, identifier, challenge):
        self.identifier = identifier
        self.value = challenge

    def convert_to_network_format(self):
        lenght = 1 + 2 + 2 + self.value.len()
        values = (0x01, self.identifier, lenght, self.value)
        packer = struct.Struct()