"""NAT Behavior Discovery Using Session Traversal Utilities for NAT (STUN)
:see: http://tools.ietf.org/html/rfc5780
"""
import struct
import stun


# Comprehension-required range (0x0000-0x7FFF):
ATTR_CHANGE_REQUEST =    0x0003
ATTR_PADDING =           0x0026
ATTR_RESPONSE_PORT =     0x0027
# Comprehension-optional range (0x8000-0xFFFF):
ATTR_RESPONSE_ORIGIN =   0x802b
ATTR_OTHER_ADDRESS =     0x802c


@stun.attribute
class ChangeRequest(stun.Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.2
    """
    type = ATTR_CHANGE_REQUEST

    @classmethod
    def decode(cls, data, offset, length):
        flags, = struct.unpack_from('>L', data, offset)
        change_ip =     flags & 0b0100
        change_port =   flags & 0b0010
        return (change_ip, change_port)


@stun.attribute
class ResponseOrigin(stun.Address):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.3
    """
    type = ATTR_RESPONSE_ORIGIN


@stun.attribute
class OtherAddress(stun.Address):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.4
    """
    type = ATTR_OTHER_ADDRESS


@stun.attribute
class ResponsePort(stun.Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.5
    """
    type = ATTR_RESPONSE_PORT

    @classmethod
    def decode(cls, data, offset, length):
        port, = struct.unpack_from('>H2x', data, offset)
        return port


@stun.attribute
class Padding(stun.Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5780#section-7.6
    """
    type = ATTR_PADDING
