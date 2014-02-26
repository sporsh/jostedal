"""Implementation of RFC 5389 Session Traversal Utilities for NAT (STUN)
:see: http://tools.ietf.org/html/rfc5389
"""

# STUN Methods Registry
METHOD_BINDING =        0x001
METHOD_SHARED_SECRET =  0x002 # (Reserved)

CLASS_REQUEST =             0x00
CLASS_INDICATION =          0x01
CLASS_RESPONSE_SUCCESS =    0x10
CLASS_RESPONSE_ERROR =      0x11


# STUN Message Types
MSG_STUN = 0b00
_MSG_TYPE = lambda METHOD, CLASS: MSG_STUN << 14 | METHOD & 0x3eef | CLASS << 4
MSG_STUN_BINDING_REQUEST          = _MSG_TYPE(METHOD_BINDING, CLASS_REQUEST)
MSG_STUN_BINDING_RESPONSE_SUCCESS = _MSG_TYPE(METHOD_BINDING, CLASS_RESPONSE_SUCCESS)
MSG_STUN_BINDING_RESPONSE_ERROR   = _MSG_TYPE(METHOD_BINDING, CLASS_RESPONSE_ERROR)

MAGIC_COOKIE = 0x2112A442

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
