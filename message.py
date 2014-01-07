"""Implementation of RFC 5389 Session Traversal Utilities for NAT (STUN)
:see: http://tools.ietf.org/html/rfc5389
"""

import struct
import socket
from operator import itemgetter
from binascii import crc32
import os


# Comprehension-required range (0x0000-0x7FFF):
ATTRIBUTE_MAPPED_ADDRESS =      0x0001
ATTRIBUTE_USERNAME =            0x0006
ATTRIBUTE_MESSAGE_INTEGRITY =   0x0008
ATTRIBUTE_ERROR_CODE =          0x0009
ATTRIBUTE_UNKNOWN_ATTRIBUTES =  0x000A
ATTRIBUTE_REALM =               0x0014
ATTRIBUTE_NONCE =               0x0015
ATTRIBUTE_XOR_MAPPED_ADDRESS =  0x0020
# Comprehension-optional range (0x8000-0xFFFF)
ATTRIBUTE_SOFTWARE =            0x8022
ATTRIBUTE_ALTERNATE_SERVER =    0x8023
ATTRIBUTE_FINGERPRINT =         0x8028

FORMAT_STUN =       0b00
FORMAT_CHANNEL =    0b10

MAGIC_COOKIE = 0x2112A442

METHOD_BINDING = 0x001

CLASS_REQUEST =             0x00
CLASS_INDICATION =          0x01
CLASS_RESPONSE_SUCCESS =    0x10
CLASS_RESPONSE_ERROR =      0x11


FAMILY_IPv4 = 0x01
FAMILY_IPv6 = 0x02
_FAMILY_TO_AF_INET = {FAMILY_IPv4: socket.AF_INET,
                      FAMILY_IPv6: socket.AF_INET6}
_AF_INET_TO_FAMILY = {socket.AF_INET: FAMILY_IPv4,
                      socket.AF_INET6: FAMILY_IPv6}
# Convert to/from STUN FAMILY and AF_INET
ftoaf = _FAMILY_TO_AF_INET.get
aftof = _AF_INET_TO_FAMILY.get


def pad(length):
    """Calculates the number of padding bytes required to align to a 4 byte boundary
    """
    return (4 - (length % 4)) % 4


class StunMessage(tuple):
    """STUN message structure
    :see: http://tools.ietf.org/html/rfc5389#section-6
    """
    msg_method = property(itemgetter(0))
    msg_class = property(itemgetter(1))
    msg_length = property(itemgetter(2))
    magic_cookie = property(itemgetter(3))
    transaction_id = property(itemgetter(4))
    attributes = property(itemgetter(5))

    _HEADER_FORMAT = '>2HL12s'
    _HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)

    _ATTR_HEADER_FORMAT = '>2H'
    _ATTR_HEADER_SIZE = struct.calcsize(_ATTR_HEADER_FORMAT)
    _ATTRIBUTE_FACTORIES = {}

    def __new__(cls, msg_method, msg_class, msg_length=0, magic_cookie=MAGIC_COOKIE,
                transaction_id=None, attributes=None):
        transaction_id = transaction_id or os.urandom(12)
        attributes = attributes or ()
        return tuple.__new__(cls, (msg_method, msg_class, msg_length,
                                   magic_cookie, transaction_id, attributes))

    def encode(self):
        msg_type = self.msg_method | self.msg_class << 4
        data = bytearray(struct.pack(self._HEADER_FORMAT,
                                     msg_type,
                                     self.msg_length,
                                     self.magic_cookie,
                                     self.transaction_id))
        for attr_type, attr_length, value in self.attributes:
            factory = self._ATTRIBUTE_FACTORIES.get(attr_type, StunMessageAttribute)
            attr_data = factory.encode(data, value)
            attr_length = len(attr_data)
            data.extend(struct.pack(self._ATTR_HEADER_FORMAT,
                                    attr_type,
                                    attr_length))
            data.extend(attr_data)
            data.extend(bytearray(pad(attr_length)))
            # Update length
            struct.pack_into('>H', data, 2, len(data) - self._HEADER_SIZE)

        return data

    @classmethod
    def decode(cls, data, offset=0, length=None):
        assert ord(data[offset]) >> 6 == FORMAT_STUN, \
            "Stun message MUST start with 0b00"
        fields = struct.unpack_from(cls._HEADER_FORMAT, data)
        (msg_type, msg_length, magic_cookie, transaction_id) = fields
        msg_type &= 0x3fff               # 00111111 11111111
        msg_method = msg_type & 0xfeef   # ..111110 11101111
        msg_class = msg_type >> 4 & 0x11 # ..000001 00010000
        offset += cls._HEADER_SIZE
        attributes = tuple(cls.decode_attributes(data, offset, msg_length))
        return cls(msg_method, msg_class, msg_length, magic_cookie,
                   transaction_id, attributes)

    @classmethod
    def decode_attributes(cls, data, offset, length):
        end = offset + length
        while offset < end:
            (attr_type, attr_length) = struct.unpack_from(
                StunMessageAttribute.HEADER_FORMAT, data, offset)
            offset += StunMessageAttribute.HEADER_SIZE
            factory = cls._ATTRIBUTE_FACTORIES.get(attr_type, UnknownAttribute)
            attr_value = factory.decode(data, offset, attr_length)
            yield factory(attr_type, attr_length, attr_value)
            offset += attr_length + pad(attr_length)

    def get_unknown_attributes(self):
        return tuple(attribute for attribute in self.attributes if
                     attribute.required and isinstance(attribute, UnknownAttribute))

    @classmethod
    def add_attribute_factory(cls, attr_type, factory):
        assert not cls._ATTRIBUTE_FACTORIES.get(attr_type, False), \
            "Duplicate factory for {:#06x}".format(attr_type)
        cls._ATTRIBUTE_FACTORIES[attr_type] = factory

    def __len__(self):
        return self._HEADER_SIZE + self.msg_length

    def __repr__(self):
        return ("{}(method={:#05x}, class={:#04x}, length={}, "
                "magic_cookie={:#010x}, transaction_id={}, attributes={})".format(
                    type(self), self.msg_method, self.msg_class, self.msg_length,
                    self.magic_cookie, self.transaction_id.encode('hex'),
                    self.attributes))


class StunMessageAttribute(tuple):
    """STUN message attribute structure
    :see: http://tools.ietf.org/html/rfc5389#section-15
    """
    HEADER_FORMAT = '>2H'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    type = property(itemgetter(0))
    length = property(itemgetter(1))
    value = property(itemgetter(2))


    def __new__(self, type_, length, value):
        self.required = type_ < 0x8000
        return tuple.__new__(self, (type_, length, value))

    @classmethod
    def encode(cls, data, value):
        return value

    @classmethod
    def decode(cls, data, offset, length):
        return data[offset:offset+length]

    def __len__(self):
        return self.HEADER_SIZE + self.length + pad(self.length)

    def __str__(self):
        return "value={!r}".format(self.value)

    def __repr__(self, *args, **kwargs):
        return "{}(type={:#06x}, length={}, {})".format(
            type(self).__name__, self.type, self.length, str(self))


class UnknownAttribute(StunMessageAttribute):
    pass


def stunattribute(attribute_type, parser=StunMessage):
    """Decorator to add a Stun Attribute as an recognized attribute type
    """
    def _decorate(cls):
        cls.TYPE = attribute_type
        parser.add_attribute_factory(attribute_type, cls)
        return cls
    return _decorate


@stunattribute(ATTRIBUTE_MAPPED_ADDRESS)
class MappedAddress(StunMessageAttribute):
    """STUN MAPPED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.1
    """
    _VALUE_FORMAT = '>xBH'
    _VALUE_SIZE = struct.calcsize(_VALUE_FORMAT)


    @classmethod
    def decode(cls, data, offset, length):
        family, port = struct.unpack_from(cls._VALUE_FORMAT, data, offset)
        offset += cls._VALUE_SIZE
        address = buffer(data, offset, length - cls._VALUE_SIZE)
        address = socket.inet_ntop(ftoaf(family), address)
        return (family, port, address)

    @classmethod
    def encode(cls, data, value):
        family, port, address = value
        address = bytearray(socket.inet_pton(ftoaf(family), address))
        return struct.pack(cls._VALUE_FORMAT, family, port) + address

    def __str__(self):
        return "family={:#04x}, port={}, address={!r}".format(*self.value)


@stunattribute(ATTRIBUTE_XOR_MAPPED_ADDRESS)
class XorMappedAddress(MappedAddress):
    """STUN XOR-MAPPED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.2
    """
    @classmethod
    def decode(cls, data, offset, length):
        family, xport = struct.unpack_from(cls._VALUE_FORMAT, data, offset)
        offset += cls._VALUE_SIZE
        if family == FAMILY_IPv4:
            xaddress = buffer(data, offset, 4)
        elif family == FAMILY_IPv6:
            xaddress = buffer(data, offset, 16)

        # xport and xaddress are xored with the concatination of
        # the magic cookie and the transaction id (data[4:20])
        magic = bytearray(*struct.unpack_from('>16s', data, 4))
        port = xport ^ magic[0] << 8 ^ magic[1]
        address = bytearray(ord(a) ^ b for a, b in zip(xaddress, magic))
        address = socket.inet_ntop(ftoaf(family), buffer(address))

        return (family, port, address)

    @classmethod
    def encode(cls, data, value):
        magic = bytearray(*struct.unpack_from('>16s', data, 4))
        family, port, address = value
        xport = port ^ magic[0] << 8 ^ magic[1]
        address = bytearray(socket.inet_pton(ftoaf(family), address))
        xaddress = bytearray(a ^ b for a, b in zip(address, magic))
        return struct.pack(cls._VALUE_FORMAT, family, xport) + xaddress


@stunattribute(ATTRIBUTE_USERNAME)
class Username(StunMessageAttribute):
    """STUN USERNAME attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.3
    """
    @classmethod
    def decode(cls, data, offset, length):
        return str(buffer(data, offset, length)).decode('utf8')

    @classmethod
    def encode(cls, data, value):
        return value.encode('utf8')


@stunattribute(ATTRIBUTE_MESSAGE_INTEGRITY)
class MessageIntegrity(StunMessageAttribute):
    """STUN MESSAGE-INTEGRITY attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.4
    """
    @classmethod
    def encode(cls, data, value):
        # long-term key
        key = md5('{}:{}:{}'.format(username, realm, password))
        # short-term key
        key = saslprep(password)

        # Checksum covers the 'length' value, so it needs to be updated first
        length = len(data) + cls._VALUE_SIZE + cls.HEADER_SIZE - StunMessage._HEADER_SIZE
        struct.pack_into('>H', data, 2, length)


@stunattribute(ATTRIBUTE_FINGERPRINT)
class Fingerprint(StunMessageAttribute):
    """STUN FINGERPRINT attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.5
    """
    MAGIC = 0x5354554e
    _VALUE_FORMAT = '>L'
    _VALUE_SIZE = struct.calcsize(_VALUE_FORMAT)

    @classmethod
    def encode(cls, data, value):
        # Checksum covers the 'length' value, so it needs to be updated first
        length = len(data) + cls._VALUE_SIZE + cls.HEADER_SIZE - StunMessage._HEADER_SIZE
        struct.pack_into('>H', data, 2, length)

        fingerprint = (crc32(data) & 0xffffffff) ^ cls.MAGIC
        return struct.pack(cls._VALUE_FORMAT, fingerprint)

    @classmethod
    def decode(cls, data, offset, length):
        fingerprint, = struct.unpack_from(cls._VALUE_FORMAT, data, offset)
        return fingerprint


@stunattribute(ATTRIBUTE_ERROR_CODE)
class ErrorCode(StunMessageAttribute):
    """STUN ERROR-CODE attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.6
    """
    _VALUE_FORMAT = '>2x2B'
    _VALUE_SIZE = struct.calcsize(_VALUE_FORMAT)

    @classmethod
    def decode(cls, data, offset, length):
        err_class, err_number = struct.unpack_from(cls._VALUE_FORMAT, data, offset)
        err_class &= 0b111
        err_reason = str(buffer(data, offset, length)).decode('utf8')
        return (err_class, err_number, err_reason)

    @classmethod
    def encode(cls, data, value):
        err_class, err_number, err_reason = value
        attr_data = struct.pack(cls._VALUE_FORMAT, err_class, err_number)
        attr_data += err_reason.encode('utf8')
        return attr_data

    def __str__(self):
        return "code={:1d}{:02d}, reason={!r}".format(*self)


@stunattribute(ATTRIBUTE_REALM)
class Realm(StunMessageAttribute):
    """STUN REALM attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.7
    """
    @classmethod
    def decode(cls, data, offset, length):
        return str(buffer(data, offset, length)).decode('utf8')

    @classmethod
    def encode(cls, data, value):
        return value.encode('utf8')


@stunattribute(ATTRIBUTE_NONCE)
class Nonce(StunMessageAttribute):
    """STUN NONCE attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.8
    """


@stunattribute(ATTRIBUTE_UNKNOWN_ATTRIBUTES)
class UnknownAttributes(StunMessageAttribute):
    """STUN UNKNOWN-ATTRIBUTES attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.9
    """
    @classmethod
    def decode(cls, data, offset, length):
        fmt = '>{}H'.format(length / 2)
        return struct.unpack_from(fmt, data, offset)

    @classmethod
    def encode(cls, data, value):
        num = len(value)
        return struct.pack('>{}H'.format(num), *value)


@stunattribute(ATTRIBUTE_SOFTWARE)
class Software(StunMessageAttribute):
    """STUN SOFTWARE attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.10
    """
    @classmethod
    def encode(cls, data, value):
        return value.encode('utf8')

    @classmethod
    def decode(cls, data, offset, length):
        return str(buffer(data, offset, length)).decode('utf8')


@stunattribute(ATTRIBUTE_ALTERNATE_SERVER)
class AlternateServer(MappedAddress):
    """STUN ALTERNATE-SERVER attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.11
    """


# ----------------------------
# RFC 5766 TURN
# ----------------------------
ATTRIBUTE_CHANNEL_NUMBER =      0x000C
ATTRIBUTE_LIFETIME =            0x000D
ATTRIBUTE_XOR_PEER_ADDRESS =    0x0012
ATTRIBUTE_DATA =                0x0013
ATTRIBUTE_XOR_RELAYED_ADDRESS = 0x0016
ATTRIBUTE_EVEN_PORT =           0x0018
ATTRIBUTE_REQUESTED_TRANSPORT = 0x0019
ATTRIBUTE_DONT_FRAGMENT =       0x001A
ATTRIBUTE_RESERVATION_TOKEN =   0x0022


@stunattribute(ATTRIBUTE_CHANNEL_NUMBER)
class ChannelNumber(StunMessageAttribute):
    """TURN STUN CHANNEL-NUMBER attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.1
    """
    @classmethod
    def decode(cls, data, offset, length):
        return struct.unpack_from('>H2x', data, offset)


@stunattribute(ATTRIBUTE_LIFETIME)
class Lifetime(StunMessageAttribute):
    """TURN STUN LIFETIME attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.2
    """


@stunattribute(ATTRIBUTE_XOR_PEER_ADDRESS)
class XorPeerAddress(XorMappedAddress):
    """TURN STUN XOR-PEER-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.3
    """


@stunattribute(ATTRIBUTE_DATA)
class Data(StunMessageAttribute):
    """TURN STUN DATA attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.4
    """


@stunattribute(ATTRIBUTE_XOR_RELAYED_ADDRESS)
class XorRelayedAddress(XorMappedAddress):
    """TURN STUN XOR-RELAYED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.5
    """


@stunattribute(ATTRIBUTE_EVEN_PORT)
class EvenPort(StunMessageAttribute):
    """TURN STUN EVEN-PORT attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.6
    """
    RESERVE = 0b10000000

    @classmethod
    def decode(cls, data, offset, length):
        return struct.unpack_from('>B', data, offset)[0] & 0b10000000


@stunattribute(ATTRIBUTE_REQUESTED_TRANSPORT)
class RequestedTransport(StunMessageAttribute):
    """TURN STUN REQUESTED-TRANSPORT attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.7
    """
    @classmethod
    def decode(cls, data, offset, length):
        protocol, = struct.unpack_from('>B3x', data, offset)
        return protocol



"""NAT Behavior Discovery Using Session Traversal Utilities for NAT (STUN)
:see: http://tools.ietf.org/html/rfc5780
"""

# Comprehension-required range (0x0000-0x7FFF):
ATTRIBUTE_CHANGE_REQUEST =    0x0003
ATTRIBUTE_PADDING =           0x0026
ATTRIBUTE_RESPONSE_PORT =     0x0027
# Comprehension-optional range (0x8000-0xFFFF):
ATTRIBUTE_RESPONSE_ORIGIN =   0x802b
ATTRIBUTE_OTHER_ADDRESS =     0x802c


@stunattribute(ATTRIBUTE_CHANGE_REQUEST)
class ChangeRequest(StunMessageAttribute):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.2
    """
    @classmethod
    def decode(cls, data, offset, length):
        flags, = struct.unpack_from('>L', data, offset)
        change_ip =     flags & 0b0100
        change_port =   flags & 0b0010
        return (change_ip, change_port)


@stunattribute(ATTRIBUTE_RESPONSE_ORIGIN)
class ResponseOrigin(MappedAddress):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.3
    """


@stunattribute(ATTRIBUTE_OTHER_ADDRESS)
class OtherAddress(MappedAddress):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.4
    """


@stunattribute(ATTRIBUTE_RESPONSE_PORT)
class ResponsePort(StunMessageAttribute):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.5
    """
    @classmethod
    def decode(cls, data, offset, length):
        port, = struct.unpack_from('>H2x', data, offset)
        return port


@stunattribute(ATTRIBUTE_PADDING)
class Padding(StunMessageAttribute):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.6
    """



if __name__ == '__main__':
    msg_data = str(bytearray.fromhex(
        "010100582112a4427a2f2b504c6a7457"
        "52616c5600200008000191170f01b020"
        "000100080001b0052e131462802b0008"
        "00010d960af0d7b4802c000800010d97"
        "0af0d7b48022001a4369747269782d31"
        "2e382e372e302027426c61636b20446f"
        "7727000080280004fd824449"))
#     msg_data = '\x01\x01\x000!\x12\xa4B\xf1\x9b\'\xa4\xac^\xe3v\x16}\xdef\x80"\x00\x16TANDBERG/4120 (X7.2.2)\x00\x00\x00 \x00\x08\x00\x01M\xae\x0f\x01\xb0 \x80(\x00\x04\x15p\x96\xbd'
#     msg_data = '\x01\x01\x000!\x12\xa4B\x0ef\xc5\xedT\x1c8\xeb\xa7\xaa\xcf:\x80"\x00\x16TANDBERG/4120 (X7.2.2)\x00\x00\x00 \x00\x08\x00\x01\xa5Z\x0f\x01\xb0 \x80(\x00\x04\xf5\xe6\x9b\xfb'
    msg = StunMessage.decode(msg_data)
    print repr(msg[:-1])
    for attribute in msg.attributes:
        print repr(attribute)

    print str(msg_data).encode('hex')
    print str(msg.encode()).encode('hex')

    msg2 = StunMessage.decode(str(msg.encode()))
    print repr(msg2[:-1])
    assert msg == msg2

    msg3 = StunMessage(METHOD_BINDING, CLASS_REQUEST,
                               attributes=[(ATTRIBUTE_SOFTWARE, 0, "Test"),
                                (ATTRIBUTE_MAPPED_ADDRESS, 0, (FAMILY_IPv4, 6666, '127.0.0.1')),
                                (ATTRIBUTE_FINGERPRINT, 0, 0)
                                ]).encode()
    print repr(msg3)
    print StunMessage.decode(str(msg3))
