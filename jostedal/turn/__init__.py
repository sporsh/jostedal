MSG_CHANNEL = 0b01


METHOD_ALLOCATE =           0x003 # only request/response semantics defined
METHOD_REFRESH =            0x004 # only request/response semantics defined
METHOD_SEND =               0x006 # only indication semantics defined
METHOD_DATA =               0x007 # only indication semantics defined
METHOD_CREATE_PERMISSION =  0x008 # only request/response semantics defined
METHOD_CHANNEL_BIND =       0x009 # only request/response semantics defined


ATTR_CHANNEL_NUMBER =      0x000C
ATTR_LIFETIME =            0x000D
ATTR_XOR_PEER_ADDRESS =    0x0012
ATTR_DATA =                0x0013
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_EVEN_PORT =           0x0018
ATTR_REQUESTED_TRANSPORT = 0x0019
ATTR_DONT_FRAGMENT =       0x001A
ATTR_RESERVATION_TOKEN =   0x0022


TRANSPORT_UDP = 0x11


# Error codes (class, number) and recommended reason phrases:
ERR_FORBIDDEN =                         4, 3, "Forbidden"
ERR_ALLOCATION_MISMATCH =               4,37, "Allocation Mismatch"
ERR_WRONG_CREDENTIALS =                 4,41, "Wrong Credentials"
ERR_UNSUPPORTED_TRANSPORT_PROTOCOL =    4,42, "Unsupported Transport Protocol"
ERR_ALLOCATION_QUOTA_REACHED =          4,86, "Allocation Quota Reached"
ERR_INSUFFICIENT_CAPACITY =             5, 8, "Insufficient Capacity"
