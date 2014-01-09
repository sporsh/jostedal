import stun
import struct
import hashlib
from twisted.internet.protocol import Protocol


MSG_CHANNEL = 0b01


METHOD_ALLOCATE =           0x003 # only request/response semantics defined
METHOD_REFRESH =            0x004 # only request/response semantics defined
METHOD_SEND =               0x006 # only indication semantics defined
METHOD_DATA =               0x007 # only indication semantics defined
METHOD_CREATE_PERMISSION =  0x008 # only request/response semantics defined
METHOD_CHANNEL_BIND =       0x009 # only request/response semantics defined


ATTR_CHANNEL_NUMBER =      0x000C, "CHANNEL-NUMBER"
ATTR_LIFETIME =            0x000D, "LIFETIME"
ATTR_XOR_PEER_ADDRESS =    0x0012, "XOR-PEER-ADDRESS"
ATTR_DATA =                0x0013, "DATA"
ATTR_XOR_RELAYED_ADDRESS = 0x0016, "XOR-RELAYED-ADDRESS"
ATTR_EVEN_PORT =           0x0018, "EVEN-PORT"
ATTR_REQUESTED_TRANSPORT = 0x0019, "REQUESTED-TRANSPORT"
ATTR_DONT_FRAGMENT =       0x001A, "DONT-FRAGMENT"
ATTR_RESERVATION_TOKEN =   0x0022, "RESERVATION-TOKEN"


TRANSPORT_UDP = 0x11


def saslprep(string):
    #TODO
    return string

def ha1(username, realm, password):
    return hashlib.md5(':'.join((username, realm, saslprep(password)))).digest()


@stun.attribute
class ChannelNumber(stun.Attribute):
    """TURN STUN CHANNEL-NUMBER attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.1
    """
    @classmethod
    def decode(cls, data, offset, length):
        return struct.unpack_from('>H2x', data, offset)
    type, name = ATTR_CHANNEL_NUMBER


@stun.attribute
class Lifetime(stun.Attribute):
    """TURN STUN LIFETIME attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.2
    """
    type, name = ATTR_LIFETIME


@stun.attribute
class XorPeerAddress(stun.Address):
    """TURN STUN XOR-PEER-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.3
    """
    type, name = ATTR_XOR_PEER_ADDRESS
    _xored = True


@stun.attribute
class Data(stun.Attribute):
    """TURN STUN DATA attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.4
    """
    type, name = ATTR_DATA


@stun.attribute
class XorRelayedAddress(stun.Address):
    """TURN STUN XOR-RELAYED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.5
    """
    type, name = ATTR_XOR_RELAYED_ADDRESS
    _xored = True


@stun.attribute
class EvenPort(stun.Attribute):
    """TURN STUN EVEN-PORT attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.6
    """
    type, name = ATTR_EVEN_PORT
    RESERVE = 0b10000000

    @classmethod
    def decode(cls, data, offset, length):
        return struct.unpack_from('>B', data, offset)[0] & 0b10000000


@stun.attribute
class RequestedTransport(stun.Attribute):
    """TURN STUN REQUESTED-TRANSPORT attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.7
    """
    type, name = ATTR_REQUESTED_TRANSPORT

    @classmethod
    def decode(cls, data, offset, length):
        protocol, = struct.unpack_from('>B3x', data, offset)
        return protocol


@stun.attribute
class DontFragment(stun.Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5766#section-14.8
    """
    type, name = ATTR_DONT_FRAGMENT


@stun.attribute
class ReservationToken(stun.Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5766#section-14.9
    """
    type, name = ATTR_RESERVATION_TOKEN


class StunState(object):
    def messageReceived(self, message):
        """Dispatches the message to correct handler
        """
        #self.dispatchMessage(message)


class Allocation(object):
    """Server side allocation
    """
    relay_transport_address = None

    # 5-tuple
    client_address = None
    client_port = None
    server_address = None
    server_port = None
    transport_protocol = None

    # Authentication information
    hmac_key = ha1('username', 'realm', 'password')
    nonce = None

    time_to_expiry = 10*60
    permissions = []#[(ipaddr, lifetime),...]
    channel_to_peer_bindings = []

    class Authenticating(): pass
    class Open(): pass
    class Expired(): pass


class AllocateTransaction(object):
    """Client side transaction for a allocation
    """
    def __init__(self):
        pass

    class StateClosed(object):
        pass
    class StateOpening(object):
        pass
    class StateOpen(object):
        LIFETIME = 10*60
        pass

class AllocateRequest(object):
    def __init__(self, transport_protocol=TRANSPORT_UDP):
        host_transport_address = self._get_transport_address()
        self.transport_protocol = transport_protocol


class StunClient(object):
    def __init__(self, server):
        self.turn_server_domain_name = None

    def send_ALLOCATE_REQUEST(self, transport_protocol=TRANSPORT_UDP,
                                time_to_expiry=None,
                                dont_fragment=False,
                                even_port=None,
                                reservation_token=None):
        """
        :param even_port: None | 0 | 1 (1==reserve next highest port number)
        :see: http://tools.ietf.org/html/rfc5766#section-6.1
        """
        msg = stun.Message.encode(METHOD_ALLOCATE, stun.CLASS_REQUEST)
        msg.add_attr(ATTR_REQUESTED_TRANSPORT, transport_protocol)
        host_transport_address = self.get_host_transport_address()
        server_transport_address = self.get_server_transport_address()
        if time_to_expiry:
            msg.add_attr(ATTR_LIFETIME, time_to_expiry)
        if dont_fragment:
            msg.add_attr(ATTR_DONT_FRAGMENT)
        if even_port is not None and not reservation_token:
            msg.add_attr(ATTR_EVEN_PORT, even_port)
        if reservation_token:
            msg.add_attr(ATTR_RESERVATION_TOKEN, even_port)

    def get_host_transport_address(self):
        pass

    def get_server_transport_address(self):
        pass #dns srv record of "turn" or "turns"

    def handle_ALLOCATE_SUCCESS_RESPONSE(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6.3
        """
        pass

    def handle_ALLOCATE_ERROR_RESPONSE(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6.4
        """
        pass

    def send_ALLOCATE_REFRESH_REQUEST(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-7.1
        """
        pass


    def handle_ALLOCATE_REFRESH_RESPONSE(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-7.3
        """
        pass


class StunServer(object):
    max_lifetime = 3600
    default_lifetime = 600

    def handle_ALLOCATE_REQUEST(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6.2
        """
        #TODO: detect retransmission, skip to success response

        # 1. require request to be authenticated
        # 2. Check if the 5-tuple is currently in use
        # 3. Check REQUESTED-TRANSPORT attribute
        requested_transport = message.get_attribute(ATTR_REQUESTED_TRANSPORT)
        if not requested_transport:
            pass # TODO: reject with 400
        if requested_transport.value != TRANSPORT_UDP:
            pass # TODO: reject with 442
        # 4. handle DONT-FRAGMENT attribute
        # 5. Check RESERVATION-TOKEN attribute
        reservation_token = message.get_attribute(ATTR_RESERVATION_TOKEN)
        even_port = message.get_attribute(ATTR_EVEN_PORT)
        if reservation_token:
            if even_port:
                pass # TODO: reject with 400
            # TODO: check that token is in range and has not expired
            # and that corresponding relayed address is still available
            # if token not valid, reject with 508
        # 6. Check EVEN-PORT
        if even_port:
            pass #TODO: if can't allocate relayed transport address, reject with 508
        # 7. reject with 486 if username allocation quota reached
        # 8. reject with 300 if we want to redirect to another server RFC5389


        # If not rejected, create allocation
        allocation = self.create_allocation()

        # Choose a relayed transport address
        if reservation_token:
            relayed_address = self.get_reserved_transport_address(reservation_token)
        if not relayed_address:
            if even_port.reserve:
                pass    #TODO: find pair of port-numbers N, N+1 on same IP where
                        #      N is even, set relayed transport addr with N and
                        #      reserve N+1 for atleast 30s (until N released)
                        #      and assign a token to that reservation
                response.add_attr(ReservationToken, token)
            elif even_port:
                pass #TODO: allocate relayed transport address with even port number
        if not relayed_address:
            pass #TODO: allocate any available relayed transport address

        # Determine initial time-to-expiry
        lifetime = message.get_attribute(ATTRIBUTE_LIFETIME)
        if lifetime:
            time_to_expiry = max(self.default_lifetime, min(self.max_lifetime, lifetime.time_to_expiry))

        response.attributes.append(XorRelayedAddress(relayed_address))
        response.attributes.append(Lifetime(time_to_expiry))
        response.attributes.append(XorMappedAddress(fivetuple))

        self.sendMessage(response)


    def hanlde_ALLOCATE_REFRESH_REQUEST(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-7.2
        """
        pass


class StunProtocol(Protocol):
    def __init__(self):
        self._state = None
        self._message_buffer = ''

    def dataReceived(self, data):
        self._message_buffer += data
        message = self._get_message()
        while message:
            self._state.messageReceived(message)
            message = self.getMessage()

    def getMessage(self):
        message = self.decodeMessage(self._message_buffer)
        self._message_buffer = self.message_buffer[len(message):]
        return message

    def sendMessage(self, message):
        self.transport.write(message.encode())
