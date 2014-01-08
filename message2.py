import struct
import os
import binascii
import socket


class StunMessage(object):
    _HEADER_FORMAT = '>2HL12s'
    _HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)

    def __init__(self, msg_method, msg_class, magic_cookie, transaction_id=None, data=None):
        self.method = msg_method
        self.msg_class = msg_class
        self.magic_cookie = magic_cookie
        transaction_id = transaction_id or os.urandom(12)
        self.data = data or bytearray()

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


class Attribute(str):
    _FORMAT = '>2H'
    _SIZE = struct.calcsize(_FORMAT)

    def __init__(self, data):
        self.value = buffer(data, Attribute._SIZE)
        self.length = len(self.value)

    def __new__(cls, data, *args):
        return str.__new__(cls, data)

    @classmethod
    def create(cls, data, **attrs):
        length = len(data)
        return type(cls.NAME, (cls,), attrs)(struct.pack(cls._FORMAT, cls.TYPE, length) + data)

    @classmethod
    def encode(cls, message, value):
        message.length += len(value)
        message.data.extend(value)

    @classmethod
    def decode(cls, data):
        return cls(data)

    def __str__(self):
        return "length={}, value={}".format(len(self), str.encode(self, 'hex'))

    def __repr__(self):
        return "{}({})".format(type(self).__name__, str(self))


def attribute(cls, data, **attrs):
    length = len(data)
    return type(cls.NAME, (cls,), attrs)(struct.pack(Attribute._FORMAT, cls.TYPE, length) + data)

FAMILY_IPv4 = 0x01
FAMILY_IPv6 = 0x02
aftof = {socket.AF_INET:  FAMILY_IPv4,
         socket.AF_INET6: FAMILY_IPv6}
ftoaf = {FAMILY_IPv4: socket.AF_INET,
         FAMILY_IPv6: socket.AF_INET6}.get


class MappedAddress(Attribute):
    type = 0x0008
    struct = struct.Struct('>BH')

    def __init__(self, value, family, port, address):
        self.family = family
        self.port = port
        self.address = address

    @classmethod
    def encode(cls, family, port, address):
        packed_ip = socket.inet_pton(ftoaf(family), address)
        data = cls.struct.pack(family, port) + packed_ip
        return cls(data, family, port, address)

    @classmethod
    def decode(cls, data):
        family, port = cls.struct.unpack_from(data)
        packed_ip = buffer(data, cls.struct.size)
        address = socket.inet_ntop(ftoaf(family), packed_ip)
        return cls(data, family, port, address)

    def __str__(self):
        return "family={:#04x}, port={}, address={!r}".format(
            self.family, self.port, self.address)


class Software(Attribute):
    TYPE = 0x1337
    @classmethod
    def encode(cls, (string,)):
        return cls(string.encode('utf8'))

    @classmethod
    def decode(cls, data):
        return data.decode('utf8')


class Fingerprint(Attribute):
    MAGIC = 0x5354554e
    _FORMAT = '>L'
    _SIZE = struct.calcsize(_FORMAT)
    @classmethod
    def encode(cls, (message,)):
        message.length += Attribute.cls._SIZE
        return cls(binascii.crc32(message) & 0xffffffff ^ cls.MAGIC)


from operator import itemgetter

class Test(tuple):
    name, type = "TUPLEATTR", 0x0080
    value = property(itemgetter(0))
    def __init__(self, *args, **kwargs):
        print args, kwargs
    def __new__(self, *args, **kwargs):
        print "NEW", args, kwargs
        return tuple.__new__(self, *args, **kwargs)
    @classmethod
    def encode(cls, family, port, address):
        data = ':'.join((family, port, address))
        header = struct.pack('>2H', cls.type, len(data))
        return cls((header + data, family, port, address))
    @classmethod
    def decode(cls, data):
        family, port, address = data.split(':')
        return cls((data, family, port, address))
    def __len__(self):
        return len(self.value)
    def __str__(self):
        return "type={:#06x}, length={}, value={}".format(self.type, len(self), self.value.encode('hex'))
    def __repr__(self):
        return "{}({})".format(self.name, self)

t = Test.encode("foo", "value1", "value2")
print repr(t)
t2 = Test.decode('666f6f3a76616c7565313a76616c756532'.decode('hex'))
print repr(t2)
print "EQ", t == t2

def decode_attrs(data):
    offset = 0
    type_, length = struct.unpack_from('>2H', data, offset)
    offset += 2
    decoder = {0x0080: Test}.get(type_)
    if not decoder:
        pass
    attr = decoder.decode(data[offset:offset+length])
    print "ATTRA", repr(attr)
decode_attrs(t.value)

class StrTest(type):
    type = 0x0080
    def __init__(self, *args, **kwargs):
        print "INIT"
        print "ARGS", args, kwargs
    def __new__(cls, data, **kwargs):
        print kwargs
        return type.__new__(cls, "STRTEST", (str,), kwargs)(data)
#         return str.__new__(cls, data)
strtest = StrTest("data", family="family", port="port", address="address")
print "STRTST", strtest.port


if __name__ == '__main__':
    attr1 = MappedAddress.decode('\x01\xff\xff\x00\x00\x00\xff')
    print attr1
    print repr(attr1)

    attr2 = MappedAddress.encode(FAMILY_IPv4, 65535, '0.0.0.255')
    print repr(attr2)
    attr2.size = 100
    attr2.foo = "bo"
    print attr2.size, attr2.foo
    print len(attr2)

    print attr1 == attr2
    print isinstance(attr1, MappedAddress)
    print isinstance(attr2, MappedAddress)
    print isinstance(attr2, Attribute)

