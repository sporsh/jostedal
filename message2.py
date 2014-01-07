import struct
import os


class StunMessage(tuple):
    _HEADER_FORMAT = '>2HL12s'
    _HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)

    def __new__(cls, msg_method, msg_class, msg_length, magic_cookie, transaction_id=None, data=None):
        cls.length = msg_length
        transaction_id = transaction_id or os.urandom(12)
        cls.data = bytearray(data or cls.encode(msg_method, msg_class, 0, magic_cookie, transaction_id))
        return tuple.__new__(cls, (msg_method, msg_class, magic_cookie, transaction_id))

#     @property
#     def length(self):
#         return len(self.data) - self._HEADER_SIZE
# 
#     @length.setter
#     def length(self, value):
#         struct.pack_into('>H', self.data, 2, value)

    @classmethod
    def encode(cls, msg_method, msg_class, msg_length, magic_cookie, transaction_id):
        msg_type = msg_method | msg_class << 4
        msg_length = 0
        return struct.pack(cls._HEADER_FORMAT, msg_type, 0, magic_cookie, transaction_id)

    @classmethod
    def decode(self, data):
        pass

    def add_attr(self, attr_type, *args):
        attr_data = attr_type.encode(self, args)
        self.data.extend(struct.pack(Attribute._FORMAT, attr_type.TYPE, len(attr_data)))
        self.data.extend(attr_data)


class Attribute(tuple):
    _FORMAT = '>2H'
    _SIZE = struct.calcsize(_FORMAT)

    def __new__(cls, type_, length, value):
        return tuple.__new__(cls, (type_, length, value))

    @classmethod
    def encode(cls, message, value):
        message.length += len(value)
        message.data.extend(value)

    @classmethod
    def decode(cls, data):
        return data


class FixedLengthAttribute(Attribute):
    def __new__(cls, value):
        return Attribute.__new__(cls, cls.TYPE, cls._LENGTH, value)


class VariableLengthAttribute(Attribute):
    def __new__(cls, value):
        length = len(value)
        return Attribute.__new__(cls, cls.TYPE, length, value)


class Software(Attribute):
    TYPE = 0x1337
    @classmethod
    def encode(cls, message, (string,)):
        return string.encode('utf8')

    @classmethod
    def decode(cls, data):
        return data.decode('utf8')


class Fingerprint(Attribute):
    @classmethod
    def encode(cls, message):
        pass


if __name__ == '__main__':
    msg = StunMessage(1, 2, 3, 4)
    msg.add_attr(Software, "test")
    print msg