"""Implementation of RFC 5389 Session Traversal Utilities for NAT (STUN)
:see: http://tools.ietf.org/html/rfc5389
"""

import os
import hmac
import struct
import socket
import hashlib
import binascii


# Comprehension-required range (0x0000-0x7FFF):
ATTR_MAPPED_ADDRESS =      0x0001
ATTR_USERNAME =            0x0006
ATTR_MESSAGE_INTEGRITY =   0x0008
ATTR_ERROR_CODE =          0x0009
ATTR_UNKNOWN_ATTRIBUTES =  0x000A
ATTR_REALM =               0x0014
ATTR_NONCE =               0x0015
ATTR_XOR_MAPPED_ADDRESS =  0x0020
# Comprehension-optional range (0x8000-0xFFFF)
ATTR_SOFTWARE =            0x8022
ATTR_ALTERNATE_SERVER =    0x8023
ATTR_FINGERPRINT =         0x8028

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


class StunMessage(bytearray):
    """STUN message structure
    :see: http://tools.ietf.org/html/rfc5389#section-6
    """
    _struct = struct.Struct('>2HL12s')
    _ATTR_TYPE_CLS = {}

    def __init__(self, data, msg_method, msg_class, magic_cookie, transaction_id):
        bytearray.__init__(self, data)
        self.msg_method = msg_method
        self.msg_class = msg_class
        self.magic_cookie = magic_cookie
        self.transaction_id = transaction_id
        self._attributes = []

    @classmethod
    def encode(cls, msg_method, msg_class, magic_cookie=MAGIC_COOKIE, transaction_id=None, data=''):
        transaction_id = transaction_id or os.urandom(12)
        msg_type = msg_method | msg_class << 4
        header = cls._struct.pack(msg_type, len(data), magic_cookie, transaction_id)
        message = cls(header, msg_method, msg_class, magic_cookie, transaction_id)
        message.extend(data)
        return message

    def add_attribute(self, attr_type, *args, **kwargs):
        attr = self.get_attr_cls(attr_type).encode(self, *args, **kwargs)
        self.extend(Attribute.struct.pack(attr.type, len(attr)))
        self.extend(attr)
        self.extend(os.urandom(pad(len(attr))))
        self._attributes.append(attr)
        #update length
        self.length = len(self) - self._struct.size
        return attr

    @classmethod
    def decode(cls, data):
        assert ord(data[0]) >> 6 == FORMAT_STUN, \
            "Stun message MUST start with 0b00"
        msg_type, msg_length, magic_cookie, transaction_id = cls._struct.unpack_from(data)
        msg_type &= 0x3fff               # 00111111 11111111
        msg_method = msg_type & 0xfeef   # ..111110 11101111
        msg_class = msg_type >> 4 & 0x11 # ..000001 00010000
        msg = cls(buffer(data, 0, cls._struct.size + msg_length),
                      msg_method, msg_class, magic_cookie, transaction_id)
        offset = cls._struct.size
        while offset < cls._struct.size + msg_length:
            attr_type, attr_length = Attribute.struct.unpack_from(data, offset)
            offset += Attribute.struct.size
            attribute = cls.get_attr_cls(attr_type).decode(data, offset, attr_length)
            msg._attributes.append(attribute)
            offset += len(attribute)
            offset += pad(len(attribute))
        return msg

    @classmethod
    def get_attr_cls(cls, attr_type):
        attr_cls = cls._ATTR_TYPE_CLS.get(attr_type)
        if not attr_cls:
            attr_cls = type('Unknown', (Unknown,), {'type': attr_type})
            cls.add_attr_cls(attr_cls)
        return attr_cls

    @classmethod
    def add_attr_cls(cls, attr_cls):
        """Decorator to add a Stun Attribute as an recognized attribute type
        """
        assert not cls._ATTR_TYPE_CLS.get(attr_cls.type, False), \
            "Duplicate definition for {:#06x}".format(attr_cls.type)
        cls._ATTR_TYPE_CLS[attr_cls.type] = attr_cls
        return attr_cls

    def unknown_required_attributes(self):
        """Returns a list of unknown comprehension-required attributes
        """
        return tuple(attribute for attribute in self._attributes if
                     attribute.type < 0x8000 and isinstance(attribute, Unknown))

    @property
    def length(self):
        return len(self) - self._struct.size

    @length.setter
    def length(self, value):
        struct.pack_into('>H', self, 2, value)

    def __repr__(self):
        return ("{}(method={:#05x}, class={:#04x}, length={}, "
                "magic_cookie={:#010x}, transaction_id={}, attributes={})".format(
                    type(self).__name__, self.msg_method, self.msg_class,
                    len(self) - self._struct.size,
                    self.magic_cookie, self.transaction_id.encode('hex'),
                    self._attributes))

    def format(self):
        return '\n'.join([
            "{0.__class__.__name__}",
            "    method:         {0.msg_method:#05x}",
            "    class:          {0.msg_class:#04x}",
            "    length:         {0.length}",
            "    magic-cookie:   {0.magic_cookie:#010x}",
            "    transaction-id: {1}",
            "    attributes:",
            ] + ["    \t" + repr(attr) for attr in self._attributes]
            ).format(self, self.transaction_id.encode('hex'))

# Decorator shortcut for adding known attribute classes
attribute = StunMessage.add_attr_cls


class Attribute(str):
    """STUN message attribute structure
    :see: http://tools.ietf.org/html/rfc5389#section-15
    """
    struct = struct.Struct('>2H')

    def __new__(cls, data, *args, **kwargs):
        return str.__new__(cls, data)

    @classmethod
    def decode(cls, data, offset, length):
        return cls(buffer(data, offset, length))

    @classmethod
    def encode(cls, msg, data):
        return cls(data)

    def __str__(self):
        return "length={}, value={}".format(
            len(self), str.encode(self, 'hex'))

    def __repr__(self):
        return "{}({})".format(type(self).__name__, str(self))


class Unknown(Attribute):
    """Base class for dynamically generated unknown STUN attributes
    """

    def __str__(self):
        return "type={:#06x}, length={}, value={}".format(
            self.type, len(self), str.encode(self, 'hex'))


class Address(Attribute):
    """Base class for all the addess STUN attributes
    """
    struct = struct.Struct('>xBH')

    def __init__(self, data, family, port, address):
        self.family = family
        self.port = port
        self.address = address

    def __str__(self):
        return "family={:#04x}, port={}, address={!r}".format(
            self.family, self.port, self.address)


@attribute
class MappedAddress(Address):
    """STUN MAPPED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.1
    """
    type = ATTR_MAPPED_ADDRESS

    @classmethod
    def decode(cls, data, offset, length):
        family, port = cls.struct.unpack_from(data, offset)
        packed_ip = buffer(data, offset + cls.struct.size, length - cls.struct.size)
        address = socket.inet_ntop(ftoaf(family), packed_ip)
        value = buffer(data, offset, length)
        return cls(value, family, port, address)

    @classmethod
    def encode(cls, msg, family, port, address):
        packed_ip = socket.inet_pton(ftoaf(family), address)
        value = cls.struct.pack(family, port) + packed_ip
        return cls(value, family, port, address)


@attribute
class XorMappedAddress(Address):
    """STUN XOR-MAPPED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.2
    """
    type = ATTR_XOR_MAPPED_ADDRESS

    @classmethod
    def decode(cls, data, offset, length):
        family, xport = cls.struct.unpack_from(data, offset)
        xaddress = buffer(data, offset + cls.struct.size, length - cls.struct.size)
        # xport and xaddress are xored with the concatination of
        # the magic cookie and the transaction id (data[4:20])
        magic = bytearray(*struct.unpack_from('>16s', data, 4))
        port = xport ^ magic[0] << 8 ^ magic[1]
        packed_ip = buffer(bytearray(ord(a) ^ b for a, b in zip(xaddress, magic)))
        address = socket.inet_ntop(ftoaf(family), packed_ip)
        value = buffer(data, offset, length)
        return cls(value, family, port, address)

    @classmethod
    def encode(cls, msg, family, port, address):
        """
        :param msg: The STUN message this attribute is to be encoded for
        """
        magic = bytearray(*struct.unpack_from('>16s', msg, 4))
        xport = port ^ magic[0] << 8 ^ magic[1]
        packed_ip = bytearray(socket.inet_pton(ftoaf(family), address))
        xaddress = bytearray(a ^ b for a, b in zip(packed_ip, magic))
        data = cls.struct.pack(family, xport) + xaddress
        return cls(data, family, port, address)


@attribute
class Username(Attribute):
    """STUN USERNAME attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.3
    """
    type = ATTR_USERNAME

    def __init__(self, data):
        self.username = str.decode(self, 'utf8')

    @classmethod
    def decode(cls, data, offset, length):
        value = buffer(data, offset, length)
        return cls(value)

    @classmethod
    def encode(cls, msg, username):
        return cls(username.encode('utf8'))

    def __str__(self):
        return repr(self.username)


@attribute
class MessageIntegrity(Attribute):
    """STUN MESSAGE-INTEGRITY attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.4
    """
    type = ATTR_MESSAGE_INTEGRITY
    _struct = struct.Struct('20s')

    @classmethod
    def encode(cls, msg, key):
#         # long-term key
#         key = md5('{}:{}:{}'.format(username, realm, password))
#         # short-term key
#         key = saslprep(password)
 
        # Checksum covers the 'length' value, so it needs to be updated first
        msg.length += cls._struct.size + Attribute.struct.size
        value = hmac.new(key, msg, hashlib.sha1).digest()
        return cls(value)


@attribute
class Fingerprint(Attribute):
    """STUN FINGERPRINT attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.5
    """
    type = ATTR_FINGERPRINT
    _struct = struct.Struct('>L')
    _MAGIC = 0x5354554e

    @classmethod
    def encode(cls, msg):
        # Checksum covers the 'length' value, so it needs to be updated first
#         length = len(msg) + cls._struct.size + Attribute.struct.size
#         struct.pack_into('>H', msg, 2, length)
        msg.length += cls._struct.size + Attribute.struct.size

        fingerprint = (binascii.crc32(msg) & 0xffffffff) ^ cls._MAGIC
        return cls(cls._struct.pack(fingerprint))

    @classmethod
    def decode(cls, data, offset, length):
        fingerprint, = cls._struct.unpack_from(data, offset)
        return cls(buffer(data, offset, length), fingerprint)


# @stunattribute(ATTRIBUTE_ERROR_CODE)
# class ErrorCode(StunMessageAttribute):
#     """STUN ERROR-CODE attribute
#     :see: http://tools.ietf.org/html/rfc5389#section-15.6
#     """
#     _VALUE_FORMAT = '>2x2B'
#     _VALUE_SIZE = struct.calcsize(_VALUE_FORMAT)
# 
#     @classmethod
#     def decode(cls, data, offset, length):
#         err_class, err_number = struct.unpack_from(cls._VALUE_FORMAT, data, offset)
#         err_class &= 0b111
#         err_reason = str(buffer(data, offset, length)).decode('utf8')
#         return (err_class, err_number, err_reason)
# 
#     @classmethod
#     def encode(cls, data, value):
#         err_class, err_number, err_reason = value
#         attr_data = struct.pack(cls._VALUE_FORMAT, err_class, err_number)
#         attr_data += err_reason.encode('utf8')
#         return attr_data
# 
#     def __str__(self):
#         return "code={:1d}{:02d}, reason={!r}".format(*self)


# @stunattribute(ATTRIBUTE_REALM)
# class Realm(StunMessageAttribute):
#     """STUN REALM attribute
#     :see: http://tools.ietf.org/html/rfc5389#section-15.7
#     """
#     @classmethod
#     def decode(cls, data, offset, length):
#         return str(buffer(data, offset, length)).decode('utf8')
# 
#     @classmethod
#     def encode(cls, data, value):
#         return value.encode('utf8')


# @stunattribute(ATTRIBUTE_NONCE)
# class Nonce(StunMessageAttribute):
#     """STUN NONCE attribute
#     :see: http://tools.ietf.org/html/rfc5389#section-15.8
#     """


# @stunattribute(ATTRIBUTE_UNKNOWN_ATTRIBUTES)
# class UnknownAttributes(StunMessageAttribute):
#     """STUN UNKNOWN-ATTRIBUTES attribute
#     :see: http://tools.ietf.org/html/rfc5389#section-15.9
#     """
#     @classmethod
#     def decode(cls, data, offset, length):
#         fmt = '>{}H'.format(length / 2)
#         return struct.unpack_from(fmt, data, offset)
# 
#     @classmethod
#     def encode(cls, data, value):
#         num = len(value)
#         return struct.pack('>{}H'.format(num), *value)


@attribute
class Software(Attribute):
    """STUN SOFTWARE attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.10
    """
    type = ATTR_SOFTWARE

    def __init__(self, data):
        self.software = str.decode(self, 'utf8')

    @classmethod
    def decode(cls, data, offset, length):
        return cls(buffer(data, offset, length))

    @classmethod
    def encode(cls, msg, software):
        return cls(software.encode('utf8'))

    def __str__(self):
        return repr(self.software)


# @stunattribute(ATTRIBUTE_ALTERNATE_SERVER)
# class AlternateServer(MappedAddress):
#     """STUN ALTERNATE-SERVER attribute
#     :see: http://tools.ietf.org/html/rfc5389#section-15.11
#     """


# # ----------------------------
# # RFC 5766 TURN
# # ----------------------------
# ATTRIBUTE_CHANNEL_NUMBER =      0x000C
# ATTRIBUTE_LIFETIME =            0x000D
# ATTRIBUTE_XOR_PEER_ADDRESS =    0x0012
# ATTRIBUTE_DATA =                0x0013
# ATTRIBUTE_XOR_RELAYED_ADDRESS = 0x0016
# ATTRIBUTE_EVEN_PORT =           0x0018
# ATTRIBUTE_REQUESTED_TRANSPORT = 0x0019
# ATTRIBUTE_DONT_FRAGMENT =       0x001A
# ATTRIBUTE_RESERVATION_TOKEN =   0x0022
# 
# 
# @stunattribute(ATTRIBUTE_CHANNEL_NUMBER)
# class ChannelNumber(StunMessageAttribute):
#     """TURN STUN CHANNEL-NUMBER attribute
#     :see: http://tools.ietf.org/html/rfc5766#section-14.1
#     """
#     @classmethod
#     def decode(cls, data, offset, length):
#         return struct.unpack_from('>H2x', data, offset)
# 
# 
# @stunattribute(ATTRIBUTE_LIFETIME)
# class Lifetime(StunMessageAttribute):
#     """TURN STUN LIFETIME attribute
#     :see: http://tools.ietf.org/html/rfc5766#section-14.2
#     """
# 
# 
# @stunattribute(ATTRIBUTE_XOR_PEER_ADDRESS)
# class XorPeerAddress(XorMappedAddress):
#     """TURN STUN XOR-PEER-ADDRESS attribute
#     :see: http://tools.ietf.org/html/rfc5766#section-14.3
#     """
# 
# 
# @stunattribute(ATTRIBUTE_DATA)
# class Data(StunMessageAttribute):
#     """TURN STUN DATA attribute
#     :see: http://tools.ietf.org/html/rfc5766#section-14.4
#     """
# 
# 
# @stunattribute(ATTRIBUTE_XOR_RELAYED_ADDRESS)
# class XorRelayedAddress(XorMappedAddress):
#     """TURN STUN XOR-RELAYED-ADDRESS attribute
#     :see: http://tools.ietf.org/html/rfc5766#section-14.5
#     """
# 
# 
# @stunattribute(ATTRIBUTE_EVEN_PORT)
# class EvenPort(StunMessageAttribute):
#     """TURN STUN EVEN-PORT attribute
#     :see: http://tools.ietf.org/html/rfc5766#section-14.6
#     """
#     RESERVE = 0b10000000
# 
#     @classmethod
#     def decode(cls, data, offset, length):
#         return struct.unpack_from('>B', data, offset)[0] & 0b10000000
# 
# 
# @stunattribute(ATTRIBUTE_REQUESTED_TRANSPORT)
# class RequestedTransport(StunMessageAttribute):
#     """TURN STUN REQUESTED-TRANSPORT attribute
#     :see: http://tools.ietf.org/html/rfc5766#section-14.7
#     """
#     UDP = 0x11
# 
#     @classmethod
#     def decode(cls, data, offset, length):
#         protocol, = struct.unpack_from('>B3x', data, offset)
#         return protocol
# 
# 
# 
# """NAT Behavior Discovery Using Session Traversal Utilities for NAT (STUN)
# :see: http://tools.ietf.org/html/rfc5780
# """
# 
# # Comprehension-required range (0x0000-0x7FFF):
# ATTRIBUTE_CHANGE_REQUEST =    0x0003
# ATTRIBUTE_PADDING =           0x0026
# ATTRIBUTE_RESPONSE_PORT =     0x0027
# # Comprehension-optional range (0x8000-0xFFFF):
# ATTRIBUTE_RESPONSE_ORIGIN =   0x802b
# ATTRIBUTE_OTHER_ADDRESS =     0x802c
# 
# 
# @stunattribute(ATTRIBUTE_CHANGE_REQUEST)
# class ChangeRequest(StunMessageAttribute):
#     """
#     :see: http://tools.ietf.org/html/rfc5780#section-7.2
#     """
#     @classmethod
#     def decode(cls, data, offset, length):
#         flags, = struct.unpack_from('>L', data, offset)
#         change_ip =     flags & 0b0100
#         change_port =   flags & 0b0010
#         return (change_ip, change_port)
# 
# 
# @stunattribute(ATTRIBUTE_RESPONSE_ORIGIN)
# class ResponseOrigin(MappedAddress):
#     """
#     :see: http://tools.ietf.org/html/rfc5780#section-7.3
#     """
# 
# 
# @stunattribute(ATTRIBUTE_OTHER_ADDRESS)
# class OtherAddress(MappedAddress):
#     """
#     :see: http://tools.ietf.org/html/rfc5780#section-7.4
#     """
# 
# 
# @stunattribute(ATTRIBUTE_RESPONSE_PORT)
# class ResponsePort(StunMessageAttribute):
#     """
#     :see: http://tools.ietf.org/html/rfc5780#section-7.5
#     """
#     @classmethod
#     def decode(cls, data, offset, length):
#         port, = struct.unpack_from('>H2x', data, offset)
#         return port
# 
# 
# @stunattribute(ATTRIBUTE_PADDING)
# class Padding(StunMessageAttribute):
#     """
#     :see: http://tools.ietf.org/html/rfc5780#section-7.6
#     """



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
    print repr(msg)
    print msg.unknown_required_attributes()
#     for attribute in msg.attributes:
#         print repr(attribute)

    print str(msg_data).encode('hex')
#     print str(msg.encode()).encode('hex')

#     msg2 = StunMessage.decode(str(msg.encode()))
#     print repr(msg2[:-1])
#     assert msg == msg2
# 
    msg3 = StunMessage.encode(METHOD_BINDING, CLASS_REQUEST)
    print str(msg3).encode('hex')
    msg3.add_attribute(ATTR_MAPPED_ADDRESS, FAMILY_IPv4, 6666, '192.168.2.1')
    msg3.add_attribute(ATTR_XOR_MAPPED_ADDRESS, FAMILY_IPv4, 6666, '192.168.2.1')
    msg3.add_attribute(ATTR_USERNAME, "testuser")
    msg3.add_attribute(ATTR_MESSAGE_INTEGRITY, 'somerandomkey')
    msg3.add_attribute(ATTR_SOFTWARE, "Test STUN Agent")
    msg3.add_attribute(ATTR_FINGERPRINT)

    print repr(msg3)
    print len(msg3)
    print repr(StunMessage.decode(str(msg3)))
#     print StunMessage.decode(str(msg3))

    print msg3.format()
