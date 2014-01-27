"""Implementation of RFC 5389 Session Traversal Utilities for NAT (STUN)
:see: http://tools.ietf.org/html/rfc5389
"""

import os
import hmac
import struct
import socket
import hashlib
import binascii


MSG_STUN =       0b00
MAGIC_COOKIE = 0x2112A442


# STUN Methods Registry
METHOD_BINDING =        0x001
METHOD_SHARED_SECRET =  0x002 # (Reserved)


CLASS_REQUEST =             0x00
CLASS_INDICATION =          0x01
CLASS_RESPONSE_SUCCESS =    0x10
CLASS_RESPONSE_ERROR =      0x11


# STUN Attribute Registry
# Comprehension-required range (0x0000-0x7FFF):
ATTR_MAPPED_ADDRESS =      0x0001
ATTR_RESPONSE_ADDRESS =    0x0002 # (Reserved)
ATTR_CHANGE_ADDRESS =      0x0003 # (Reserved)
ATTR_SOURCE_ADDRESS =      0x0004 # (Reserved)
ATTR_CHANGED_ADDRESS =     0x0005 # (Reserved)
ATTR_USERNAME =            0x0006
ATTR_PASSWORD =            0x0007 # (Reserved)
ATTR_MESSAGE_INTEGRITY =   0x0008
ATTR_ERROR_CODE =          0x0009
ATTR_UNKNOWN_ATTRIBUTES =  0x000A
ATTR_REFLECTED_FROM =      0x000B # (Reserved)
ATTR_REALM =               0x0014
ATTR_NONCE =               0x0015
ATTR_XOR_MAPPED_ADDRESS =  0x0020
# Comprehension-optional range (0x8000-0xFFFF):
ATTR_SOFTWARE =            0x8022
ATTR_ALTERNATE_SERVER =    0x8023
ATTR_FINGERPRINT =         0x8028

# Ignored comprehension required attributes for RFC 3489 compability
IGNORED_ATTRS = [ATTR_RESPONSE_ADDRESS, ATTR_CHANGE_ADDRESS,
                 ATTR_SOURCE_ADDRESS, ATTR_CHANGED_ADDRESS,
                 ATTR_PASSWORD, ATTR_REFLECTED_FROM]

# Error codes (class, number) and recommended reason phrases:
ERR_TRY_ALTERNATE =     3, 0, "Try Alternate"
ERR_BAD_REQUEST =       4, 0, "Bad Request"
ERR_UNAUTHORIZED =      4, 1, "Unauthorized"
ERR_UNKNOWN_ATTRIBUTE = 4,20, "Unknown Attribute"
ERR_STALE_NONCE =       4,38, "Stale Nonce"
ERR_SERVER_ERROR =      5, 0, "Server Error"


def saslprep(string):
    #TODO
    return string

def ha1(username, realm, password):
    return hashlib.md5(':'.join((username, realm, saslprep(password)))).digest()


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

    def add_attr(self, attr_cls, *args, **kwargs):
        attr = attr_cls.encode(self, *args, **kwargs)
        self.extend(Attribute.struct.pack(attr.type, len(attr)))
        self.extend(attr)
        self.extend(os.urandom(attr.padding))
        self._attributes.append(attr)
        #update length
        self.length = len(self) - self._struct.size
        return attr

    def get_attr(self, *attr_types):
        for attr in self._attributes:
            if attr.type in attr_types:
                return attr

    @classmethod
    def decode(cls, data):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.1
        """
        assert ord(data[0]) >> 6 == MSG_STUN, \
            "Stun message MUST start with 0b00"
        msg_type, msg_length, magic_cookie, transaction_id = cls._struct.unpack_from(data)
#         assert magic_cookie == MAGIC_COOKIE, \
#             "Incorrect magic cookie ({:#x})".format(magic_cookie)
        assert msg_length % 4 == 0, \
            "Message not aliged to 4 byte boundary"
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
        print "*** Registered attribute {0.type:#06x}={0.__name__}".format(attr_cls)
        assert not cls._ATTR_TYPE_CLS.get(attr_cls.type, False), \
            "Duplicate definition for {:#06x}".format(attr_cls.type)
        cls._ATTR_TYPE_CLS[attr_cls.type] = attr_cls
        return attr_cls

    def unknown_comp_required_attrs(self, ignored=()):
        """Returns a list of unknown comprehension-required attributes
        """
        return tuple(attr.type for attr in self._attributes
                     if attr.type not in ignored
                     and attr.required
                     and isinstance(attr, Unknown))

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
        return attr_cls.__name__ if attr_cls else "{:#06x}".format(attr_type)

    def __repr__(self):
        return ("{}(method={:#05x}, class={:#04x}, length={}, "
                "magic_cookie={:#010x}, transaction_id={}, attributes={})".format(
                    type(self).__name__, self.msg_method, self.msg_class,
                    len(self) - self._struct.size,
                    self.magic_cookie, self.transaction_id.encode('hex'),
                    self._attributes))

    def format(self):
        string = '\n'.join([
            "{0.__class__.__name__}",
            "    method:         {0.msg_method:#05x}",
            "    class:          {0.msg_class:#04x}",
            "    length:         {0.length}",
            "    magic-cookie:   {0.magic_cookie:#010x}",
            "    transaction-id: {1}",
            "    attributes:", ""
            ]).format(self, self.transaction_id.encode('hex'))
        string += '\n'.join(["    \t" + repr(attr) for attr in self._attributes])
        return string


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
        """Establish wether a attribute is in the comprehension-required range
        """
        #Comprehension-required attributes are in range 0x0000-0x7fff
        return self.type < 0x8000

#     def __repr__(self):
#         return "{}(length={}, value={})".format(type(self).__name__, len(self),
#                                                 str.encode(self, 'hex'))


class Unknown(Attribute):
    """Base class for dynamically generated unknown STUN attributes
    """
    def __repr__(self):
        return "UNKNOWN(type={:#06x}, length={}, value={})".format(
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
        xport = port
        packed_ip = socket.inet_pton(Address.ftoaf(family), address)
        if cls._xored:
            magic = bytearray(*struct.unpack_from('>16s', msg, 4))
            xport = port ^ magic[0] << 8 ^ magic[1]
            packed_ip = bytearray(ord(a) ^ b for a, b in zip(packed_ip, magic))
        data = cls.struct.pack(family, xport) + packed_ip
        return cls(data, family, port, address)

    def __repr__(self):
        return "{}(family={:#04x}, port={}, address={!r})".format(
            type(self).__name__, self.family, self.port, self.address)


@attribute
class MappedAddress(Address):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.1
    """
    type = ATTR_MAPPED_ADDRESS
    _xored = False


@attribute
class Username(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.3
    """
    type = ATTR_USERNAME

    @classmethod
    def encode(cls, msg, username):
        return cls(username.encode('utf8'))

    def __repr__(self, *args, **kwargs):
        return "USERNAME({!r})".format(str(self))


@attribute
class MessageIntegrity(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.4
    """
    type = ATTR_MESSAGE_INTEGRITY
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

    def __repr__(self):
        return "MESSAGE-INTEGRITY({})".format(str.encode(self, 'hex'))


@attribute
class ErrorCode(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.6
    """
    type = ATTR_ERROR_CODE
    _struct = struct.Struct('>2x2B')

    def __init__(self, data, err_class, err_number, reason):
        self.err_class = err_class
        self.err_number = err_number
        self.code = err_class * 100 + err_number
        self.reason = str(reason).decode('utf8')

    @classmethod
    def decode(cls, data, offset, length):
        err_class, err_number = cls._struct.unpack_from(data, offset)
        err_class &= 0b111
        value = buffer(data, offset, length)
        reason = buffer(value, cls._struct.size)
        return cls(value, err_class, err_number, reason)

    @classmethod
    def encode(cls, msg, err_class, err_number, reason):
        value = cls._struct.pack(err_class, err_number)
        reason = reason.encode('utf8')
        return cls(value + reason, err_class, err_number, reason)

    def __repr__(self):
        return "ERROR-CODE(code={}, reason={!r})".format(self.code, self.reason)


@attribute
class UnknownAttributes(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.9
    """
    type = ATTR_UNKNOWN_ATTRIBUTES

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

    def __repr__(self):
        return "UNKNOWN-ATTRIBUTES({})".format(
            str(["{:#06x}".format(t) for t in self.types]))


@attribute
class Realm(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.7
    """
    type = ATTR_REALM

    @classmethod
    def encode(cls, msg, realm):
        return cls(realm.encode('utf8'))

    def __repr__(self):
        return "REALM({})".format(str.__repr__(self))


@attribute
class Nonce(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.8
    """
    type = ATTR_NONCE
    _max_length = 763 # less than 128 characters can be up to 763 bytes

    def __repr__(self):
        return "NONCE({})".format(str.__repr__(self))


@attribute
class XorMappedAddress(Address):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.2
    """
    type = ATTR_XOR_MAPPED_ADDRESS
    _xored = True


@attribute
class Software(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.10
    """
    type = ATTR_SOFTWARE

    @classmethod
    def encode(cls, msg, software):
        return cls(software.encode('utf8'))

    def __repr__(self):
        return "SOFTWARE({})".format(str.__repr__(self))


@attribute
class AlternateServer(Address):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.11
    """
    type = ATTR_ALTERNATE_SERVER


@attribute
class Fingerprint(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.5
    """
    type = ATTR_FINGERPRINT
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

    def __repr__(self, *args, **kwargs):
        return "FINGERPRINT(0x{})".format(str.encode(self, 'hex'))

if __name__ == '__main__':
    msg_data = (
        '010100582112a4427a2f2b504c6a7457'
        '52616c5600200008000191170f01b020'
        '000100080001b0052e131462802b0008'
        '00010d960af0d7b4802c000800010d97'
        '0af0d7b48022001a4369747269782d31'
        '2e382e372e302027426c61636b20446f'
        '7727000080280004fd824449'
        ).decode('hex')

    msg_data = (
        '011300602112a442fedcb2d51f23946d'
        '9cc9754e0009001000000401556e6175'
        '74686f72697365640015001036303332'
        '3763313731343561373738380014000a'
        '7765627274632e6f72678e4f8022001a'
        '4369747269782d312e382e372e302027'
        '426c61636b20446f77270004'
        '802800045a4c0c70' # Fingerprint
        ).decode('hex')

#     msg_data = (
#         '010100302112a442f19b27a4ac5ee376'
#         '167dde668022001654414e4442455247'
#         '2f34313230202858372e322e32290000'
#         '0020000800014dae0f01b02080280004'
#         '157096bd'
#         ).decode('hex')

#     msg_data = (
#         '010100302112a4420e66c5ed541c38eb'
#         'a7aacf3a8022001654414e4442455247'
#         '2f34313230202858372e322e32290000'
#         '002000080001a55a0f01b02080280004'
#         'f5e69bfb'
#         ).decode('hex')

    msg = Message.decode(msg_data)
    print msg.format()
    print msg_data.encode('hex')

    msg3 = Message.encode(METHOD_BINDING, CLASS_REQUEST)
    msg3.add_attr(type('Foo', (Unknown,), {'type': 0x6666}), 'data')
    msg3.add_attr(MappedAddress, Address.FAMILY_IPv4, 1337, '192.168.2.255')
    msg3.add_attr(Username, "johndoe")
    msg3.add_attr(MessageIntegrity, ha1('username', 'realm', 'password'))
    msg3.add_attr(ErrorCode, *ERR_SERVER_ERROR)
    msg3.add_attr(UnknownAttributes, [0x1337, 0xb00b, 0xbeef])
    msg3.add_attr(Realm, "pexip.com")
    msg3.add_attr(Nonce, '36303332376331373134356137373838'.decode('hex'))
    msg3.add_attr(XorMappedAddress, Address.FAMILY_IPv4, 1337, '192.168.2.255')
    msg3.add_attr(Software, u"\u8774\u8776 h\xfadi\xe9 'butterfly'")
    msg3.add_attr(AlternateServer, Address.FAMILY_IPv4, 8008, '192.168.2.128')
    msg3.add_attr(Fingerprint)
    print str(msg3).encode('hex')
    print msg3.format()
    print Message.decode(str(msg3)).format()
