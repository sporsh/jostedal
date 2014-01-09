"""Implementation of RFC 5389 Session Traversal Utilities for NAT (STUN)
:see: http://tools.ietf.org/html/rfc5389
"""

import os
import hmac
import struct
import socket
import hashlib
import binascii


FORMAT_STUN =       0b00
MAGIC_COOKIE = 0x2112A442

# STUN Methods Registry
#                0x000 (Reserved)
METHOD_BINDING = 0x001
#                0x002 (Reserved; was SharedSecret)

CLASS_REQUEST =             0x00
CLASS_INDICATION =          0x01
CLASS_RESPONSE_SUCCESS =    0x10
CLASS_RESPONSE_ERROR =      0x11

# STUN Attribute Registry
# Comprehension-required range (0x0000-0x7FFF):
ATTR_MAPPED_ADDRESS =      0x0001, "MAPPED-ADDRESS"
#                          0x0002 (Reserved; was RESPONSE-ADDRESS
#                          0x0003 (Reserved; was CHANGE-ADDRESS)
#                          0x0004 (Reserved; was SOURCE-ADDRESS)
#                          0x0005 (Reserved; was CHANGED-ADDRESS)
ATTR_USERNAME =            0x0006, "USERNAME"
#                          0x0007 (Reserved; was PASSWORD)
ATTR_MESSAGE_INTEGRITY =   0x0008, "MESSAGE-INTEGRITY"
ATTR_ERROR_CODE =          0x0009, "ERROR-CODE"
ATTR_UNKNOWN_ATTRIBUTES =  0x000A, "UNKNOWN-ATTRIBUTES"
#                          0x000B (Reserved; was REFLECTED-FROM)
ATTR_REALM =               0x0014, "REALM"
ATTR_NONCE =               0x0015, "NONCE"
ATTR_XOR_MAPPED_ADDRESS =  0x0020, "XOR-MAPPED-ADDRESS"
# Comprehension-optional range (0x8000-0xFFFF):
ATTR_SOFTWARE =            0x8022, "SOFTWARE"
ATTR_ALTERNATE_SERVER =    0x8023, "ALTERNATE-SERVER"
ATTR_FINGERPRINT =         0x8028, "FINGERPRINT"

# Error codes (class, number) and recommended reason phrases:
ERR_TRY_ALTERNATE =     3,00, "Try Alternate"
ERR_BAD_REQUEST =       4,00, "Bad Request"
ERR_UNAUTHORIZED =      4,01, "Unauthorized"
ERR_UNKNOWN_ATTRIBUTE = 4,20, "Unknown Attribute"
ERR_STALE_NONCE =       4,38, "Stale Nonce"
ERR_SERVER_ERROR =      5,00, "Server Error"


class Message(bytearray):
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

    def add_attribute(self, attr_cls, *args, **kwargs):
        attr = attr_cls.encode(self, *args, **kwargs)
        self.extend(Attribute.struct.pack(attr.type, len(attr)))
        self.extend(attr)
        self.extend(os.urandom(attr.padding))
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
            attr = cls.get_attr_cls(attr_type).decode(data, offset, attr_length)
            msg._attributes.append(attr)
            offset += len(attr)
            offset += attr.padding
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
        print "*** Registered attribute {0.type:#06x}={0.name}".format(attr_cls)
        assert not cls._ATTR_TYPE_CLS.get(attr_cls.type, False), \
            "Duplicate definition for {:#06x}".format(attr_cls.type)
        cls._ATTR_TYPE_CLS[attr_cls.type] = attr_cls
        return attr_cls

    def unknown_comp_required_attrs(self):
        """Returns a list of unknown comprehension-required attributes
        """
        return tuple(attr.type for attr in self._attributes if
            attr.required and isinstance(attr, Unknown))

    @property
    def length(self):
        return len(self) - self._struct.size

    @length.setter
    def length(self, value):
        struct.pack_into('>H', self, 2, value)

    @classmethod
    def attr_name(cls, attr_type):
        """Get the readable name of an attribute type, if known
        """
        attr_cls = cls._ATTR_TYPE_CLS.get(attr_type)
        return attr_cls.name if attr_cls else "{:#06x}".format(attr_type)

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
attribute = Message.add_attr_cls


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

    @property
    def padding(self):
        """Calculate number of padding bytes required to align to 4 byte boundary
        """
        return (4 - (len(self) % 4)) % 4

    @property
    def required(self):
        """Establish wether a attribute is required or not
        """
        #Comprehension-required attributes are in range 0x0000-0x7fff
        return self.type < 0x8000

    def __str__(self):
        return "length={}, value={}".format(
            len(self), str.encode(self, 'hex'))

    def __repr__(self):
        return "{}({})".format(self.name, str(self))


class Unknown(Attribute):
    """Base class for dynamically generated unknown STUN attributes
    """
    name = 'UNKNOWN'

    def __str__(self):
        return "type={:#06x}, length={}, value={}".format(
            self.type, len(self), str.encode(self, 'hex'))


class Address(Attribute):
    """Base class for all the addess STUN attributes
    :cvar _xored: Wether or not the port and address field are xored
    """
    struct = struct.Struct('>xBH')

    FAMILY_IPv4 = 0x01
    FAMILY_IPv6 = 0x02
    # Convert to/from STUN FAMILY and AF_INET
    ftoaf = {FAMILY_IPv4: socket.AF_INET,
             FAMILY_IPv6: socket.AF_INET6}.get
    aftof = {socket.AF_INET: FAMILY_IPv4,
             socket.AF_INET6: FAMILY_IPv6}.get

    _xored = False

    def __init__(self, data, family, port, address):
        self.family = family
        self.port = port
        self.address = address

    @classmethod
    def decode(cls, data, offset, length):
        family, port = cls.struct.unpack_from(data, offset)
        packed_ip = buffer(data, offset + cls.struct.size, length - cls.struct.size)
        if cls._xored:
            # xport and xaddress are xored with the concatination of
            # the magic cookie and the transaction id (data[4:20])
            magic = bytearray(*struct.unpack_from('>16s', data, 4))
            port = port ^ magic[0] << 8 ^ magic[1]
            packed_ip = buffer(bytearray(ord(a) ^ b for a, b in zip(packed_ip, magic)))
        address = socket.inet_ntop(Address.ftoaf(family), packed_ip)
        value = buffer(data, offset, length)
        return cls(value, family, port, address)

    @classmethod
    def encode(cls, msg, family, port, address):
        packed_ip = socket.inet_pton(Address.ftoaf(family), address)
        if cls._xored:
            magic = bytearray(*struct.unpack_from('>16s', msg, 4))
            port = port ^ magic[0] << 8 ^ magic[1]
            packed_ip = bytearray(ord(a) ^ b for a, b in zip(packed_ip, magic))
        data = cls.struct.pack(family, port) + packed_ip
        return cls(data, family, port, address)

    def __str__(self):
        return "family={:#04x}, port={}, address={!r}".format(
            self.family, self.port, self.address)


@attribute
class MappedAddress(Address):
    """STUN MAPPED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.1
    """
    type, name = ATTR_MAPPED_ADDRESS
    _xored = False


@attribute
class XorMappedAddress(Address):
    """STUN XOR-MAPPED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.2
    """
    type, name = ATTR_XOR_MAPPED_ADDRESS
    _xored = True


@attribute
class Username(Attribute):
    """STUN USERNAME attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.3
    """
    type, name = ATTR_USERNAME

    def __init__(self, data):
        self.username = str.decode(self, 'utf8')

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
    type, name = ATTR_MESSAGE_INTEGRITY
    _struct = struct.Struct('20s')

    @classmethod
    def encode(cls, msg, key):
        """
        :param key: H(A1) for long-term, SASLprep(password) for short-term auth
        """
        # HMAC covers the 'length' value of msg, so it needs to be updated first
        msg.length += cls._struct.size + Attribute.struct.size

        value = hmac.new(key, msg, hashlib.sha1).digest()
        return cls(value)


@attribute
class Fingerprint(Attribute):
    """STUN FINGERPRINT attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.5
    """
    type, name = ATTR_FINGERPRINT
    _struct = struct.Struct('>L')
    _MAGIC = 0x5354554e

    @classmethod
    def encode(cls, msg):
        # Checksum covers the 'length' value, so it needs to be updated first
        msg.length += cls._struct.size + Attribute.struct.size

        fingerprint = (binascii.crc32(msg) & 0xffffffff) ^ cls._MAGIC
        return cls(cls._struct.pack(fingerprint))

    @classmethod
    def decode(cls, data, offset, length):
        fingerprint, = cls._struct.unpack_from(data, offset)
        return cls(buffer(data, offset, length), fingerprint)


@attribute
class ErrorCode(Attribute):
    """STUN ERROR-CODE attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.6
    """
    type, name = ATTR_ERROR_CODE
    _struct = struct.Struct('>2x2B')

    def __init__(self, data, err_class, err_number, reason):
        self.err_class = err_class
        self.err_number = err_number
        self.code = err_class * 10 + err_number
        self.reason = reason.decode('utf8')

    @classmethod
    def decode(cls, data, offset, length):
        err_class, err_number = cls._struct.unpack_from(data, offset)
        err_class &= 0b111
        value = buffer(data, offset, length)
        reason = buffer(value, cls._struct.size)
        return cls(value, err_class, err_number, reason)

    @classmethod
    def encode(cls, msg, err_class, err_number, reason):
        value = struct.pack(cls._VALUE_FORMAT, err_class, err_number)
        reason = reason.encode('utf8')
        return cls(value + reason, err_class, err_number, reason)

    def __str__(self):
        return "code={}, reason={!r}".format(self.code, self.reason)


@attribute
class Realm(Attribute):
    """STUN REALM attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.7
    """
    type, name = ATTR_REALM

    def __init__(self, data):
        self.realm = str.decode(self, 'utf8')

    @classmethod
    def encode(cls, data, realm):
        return cls(realm.encode('utf8'))

    def __str__(self):
        return repr(self.software)


@attribute
class Nonce(Attribute):
    """STUN NONCE attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.8
    """
    type, name = ATTR_NONCE
    _max_length = 763 # less than 128 characters can be up to 763 bytes

@attribute
class UnknownAttributes(Attribute):
    """STUN UNKNOWN-ATTRIBUTES attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.9
    """
    type, name = ATTR_UNKNOWN_ATTRIBUTES

    def __init__(self, data, types):
        self.types = types

    @classmethod
    def decode(cls, data, offset, length):
        types = struct.unpack_from('>{}H'.format(length // 2), data, offset)
        return cls(buffer(data, offset, length), types)

    @classmethod
    def encode(cls, msg, types):
        num = len(types)
        return cls(struct.pack('>{}H'.format(num), *types), types)

    def __str__(self):
        return str([("{:#06x}".format(t) for t in self.types)])


@attribute
class Software(Attribute):
    """STUN SOFTWARE attribute
    :see: http://tools.ietf.org/html/rfc5389#section-15.10
    """
    type, name = ATTR_SOFTWARE

    def __init__(self, data):
        self.software = str.decode(self, 'utf8')

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


if __name__ == '__main__':
    from rfc5780 import OtherAddress
    attribute(OtherAddress)
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
    msg = Message.decode(msg_data)
    print msg.format()
#     for attribute in msg.attributes:
#         print repr(attribute)

    print str(msg_data).encode('hex')
#     print str(msg.encode()).encode('hex')

#     msg2 = Message.decode(str(msg.encode()))
#     print repr(msg2[:-1])
#     assert msg == msg2
# 
    msg3 = Message.encode(METHOD_BINDING, CLASS_REQUEST)
    print str(msg3).encode('hex')
    msg3.add_attribute(MappedAddress, Address.FAMILY_IPv4, 6666, '192.168.2.1')
    msg3.add_attribute(XorMappedAddress, Address.FAMILY_IPv4, 6666, '192.168.2.1')
    msg3.add_attribute(Username, "testuser")
    msg3.add_attribute(MessageIntegrity, 'somerandomkey')
    msg3.add_attribute(Software, "Test STUN Agent")
    msg3.add_attribute(Fingerprint)

    print repr(msg3)
    print len(msg3)
    print repr(Message.decode(str(msg3)))
#     print Message.decode(str(msg3))

    print msg3.format()
