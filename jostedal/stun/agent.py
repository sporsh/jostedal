import logging
from twisted.internet.protocol import DatagramProtocol
from jostedal import stun
import struct
import os
import socket


logger = logging.getLogger(__name__)


class StunUdpProtocol(DatagramProtocol):
    def __init__(self, reactor, interface, port, software, RTO=3., Rc=7, Rm=16):
        """
        :param port: UDP port to bind to
        :param RTO: Retransmission TimeOut (initial value)
        :param Rc: Retransmission Count (maximum number of request to send)
        :param Rm: Retransmission Multiplier (timeout = Rm * RTO)
        """
        self.reactor = reactor
        self.interface = interface
        self.port = port
        self.software = software
        self.RTO = .5
        self.Rc = 7
        self.timeout = Rm * RTO

        self._handlers = {
            # Binding handlers
            (stun.METHOD_BINDING, stun.CLASS_REQUEST):
                self._stun_binding_request,
            (stun.METHOD_BINDING, stun.CLASS_INDICATION):
                self._stun_binding_indication,
            (stun.METHOD_BINDING, stun.CLASS_RESPONSE_SUCCESS):
                self._stun_binding_success,
            (stun.METHOD_BINDING, stun.CLASS_RESPONSE_ERROR):
                self._stun_binding_error,
            }

    def start(self):
        port = self.reactor.listenUDP(self.port, self, self.interface)
        return port.port

    def datagramReceived(self, datagram, addr):
        msg_type = ord(datagram[0]) >> 6
        if msg_type == stun.MSG_STUN:
            try:
                msg = Message.decode(datagram)
            except Exception:
                logger.exception("Failed to decode STUN from %s:%d:", *addr)
                logger.debug(datagram.encode('hex'))
            else:
                if isinstance(msg, Message):
                    self._stun_received(msg, addr)
        else:
            logger.warning("Unknown message in datagram from %s:%d:", *addr)
            logger.debug(datagram.encode('hex'))

    def _stun_received(self, msg, addr):
        handler = self._handlers.get((msg.msg_method, msg.msg_class))
        if handler:
            logger.info("%s Received STUN", self)
            logger.debug(msg.format())
            handler(msg, addr)
        else:
            logger.info("%s Received unrecognized STUN", self)
            logger.debug(msg.format())

    def _stun_unhandeled(self, msg, addr):
        logger.warning("%s Unhandeled message from %s:%d", self, *addr)
        logger.debug(msg.format())

    def _stun_binding_request(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_indication(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_success(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_error(self, msg, addr):
        self._stun_unhandeled(msg, addr)


class Message(bytearray):
    """STUN message structure
    :see: http://tools.ietf.org/html/rfc5389#section-6
    """

    _struct = struct.Struct('>2HL12s')
    _ATTR_TYPE_CLS = {}

    _padding = os.urandom

    def __init__(self, data, msg_method, msg_class, magic_cookie, transaction_id):
        bytearray.__init__(self, data)
        self.msg_method = msg_method
        self.msg_class = msg_class
        self.magic_cookie = magic_cookie
        self.transaction_id = transaction_id
        self._attributes = []

    @classmethod
    def encode(cls, msg_method, msg_class, magic_cookie=stun.MAGIC_COOKIE, transaction_id=None, data=''):
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
        self.extend(self._padding(attr.padding))
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
        assert ord(data[0]) >> 6 == stun.MSG_STUN, \
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

    def create_response(self, msg_class):
        return self.encode(self.msg_method, msg_class, self.magic_cookie,
                           self.transaction_id)

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


# Decorator shortcut for adding known attribute classes
attribute = Message.add_attr_cls
