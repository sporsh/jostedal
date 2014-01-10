import stun
import struct
from stun_agent import StunUdpClient, StunUdpServer


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


@stun.attribute
class ChannelNumber(stun.Attribute):
    """TURN STUN CHANNEL-NUMBER attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.1
    """
    @classmethod
    def decode(cls, data, offset, length):
        return struct.unpack_from('>H2x', data, offset)
    type = ATTR_CHANNEL_NUMBER


@stun.attribute
class Lifetime(stun.Attribute):
    """TURN STUN LIFETIME attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.2
    """
    type = ATTR_LIFETIME


@stun.attribute
class XorPeerAddress(stun.Address):
    """TURN STUN XOR-PEER-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.3
    """
    type = ATTR_XOR_PEER_ADDRESS
    _xored = True


@stun.attribute
class Data(stun.Attribute):
    """TURN STUN DATA attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.4
    """
    type = ATTR_DATA


@stun.attribute
class XorRelayedAddress(stun.Address):
    """TURN STUN XOR-RELAYED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.5
    """
    type = ATTR_XOR_RELAYED_ADDRESS
    _xored = True


@stun.attribute
class EvenPort(stun.Attribute):
    """TURN STUN EVEN-PORT attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.6
    """
    type = ATTR_EVEN_PORT
    RESERVE = 0b10000000

    @classmethod
    def decode(cls, data, offset, length):
        return struct.unpack_from('>B', data, offset)[0] & 0b10000000


@stun.attribute
class RequestedTransport(stun.Attribute):
    """TURN STUN REQUESTED-TRANSPORT attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.7
    """
    type = ATTR_REQUESTED_TRANSPORT
    _struct = struct.Struct('>B3x')

    def __init__(self, data, protocol):
        self.protocol = protocol

    @classmethod
    def encode(cls, msg, protocol):
        return cls(cls._struct.pack(protocol), protocol)

    @classmethod
    def decode(cls, data, offset, length):
        protocol, = cls._struct.unpack_from(data, offset)
        return cls(buffer(data, offset, length), protocol)


@stun.attribute
class DontFragment(stun.Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5766#section-14.8
    """
    type = ATTR_DONT_FRAGMENT


@stun.attribute
class ReservationToken(stun.Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5766#section-14.9
    """
    type = ATTR_RESERVATION_TOKEN


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
    hmac_key = stun.ha1('username', 'realm', 'password')
    nonce = None

    time_to_expiry = 10*60
    permissions = []#[(ipaddr, lifetime),...]
    channel_to_peer_bindings = []

    class Authenticating(): pass
    class Open(): pass
    class Expired(): pass


class TurnUdpClient(StunUdpClient):
    def __init__(self, reactor):
        StunUdpClient.__init__(self, reactor)
        self.turn_server_domain_name = None

        self._handlers.update({
            # Allocate handlers
            (METHOD_ALLOCATE, stun.CLASS_RESPONSE_SUCCESS):
                self._stun_allocate_success,
            (METHOD_ALLOCATE, stun.CLASS_RESPONSE_ERROR):
                self._stun_allocate_error,
            # Refresh handlers
            (METHOD_REFRESH, stun.CLASS_RESPONSE_SUCCESS):
                self._stun_refresh_success,
            (METHOD_REFRESH, stun.CLASS_RESPONSE_ERROR):
                self._stun_refresh_error,
            # Data handlers
            (METHOD_DATA, stun.CLASS_INDICATION):
                self._stun_data_indication,
            })

    def allocate(self, addr, transport=TRANSPORT_UDP, time_to_expiry=None,
        dont_fragment=False, even_port=None, reservation_token=None):
        """
        :param even_port: None | 0 | 1 (1==reserve next highest port number)
        :see: http://tools.ietf.org/html/rfc5766#section-6.1
        """
        request = stun.Message.encode(METHOD_ALLOCATE, stun.CLASS_REQUEST)
        request.add_attr(RequestedTransport, transport)
        if time_to_expiry:
            request.add_attr(ATTR_LIFETIME, time_to_expiry)
        if dont_fragment:
            request.add_attr(ATTR_DONT_FRAGMENT)
        if even_port is not None and not reservation_token:
            request.add_attr(ATTR_EVEN_PORT, even_port)
        if reservation_token:
            request.add_attr(ATTR_RESERVATION_TOKEN, even_port)
        return self.request(request, addr)

    def refresh(self, time_to_expiry):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6
        """
        request = stun.Message.encode(METHOD_REFRESH, stun.CLASS_REQUEST)
        if time_to_expiry:
            request.add_attr(ATTR_LIFETIME, time_to_expiry)

    def get_host_transport_address(self):
        pass

    def get_server_transport_address(self):
        pass #dns srv record of "turn" or "turns"

    def _stun_allocate_success(self, msg, addr):
        transaction = self._transactions.get(msg.transaction_id)
        if transaction:
            relayed_addr = msg.get_attr(ATTR_XOR_RELAYED_ADDRESS)
            if relayed_addr:
                transaction.succeed(str(relayed_addr))
            else:
                transaction.fail(Exception("No allocation in response"))

    def _stun_allocate_error(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_refresh_success(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_refresh_error(self, msg, addr):
        # If time_to_expiry == 0 and error 437 (Allocation Mismatch)
        # consider transaction a success
        self.errback(msg.format())

    def _stun_data_indication(self, msg, addr):
        self._stun_unhandeled(msg, addr)


class TurnUdpServer(StunUdpServer):
    max_lifetime = 3600
    default_lifetime = 600

    def __init__(self, reactor, port=3478):
        StunUdpServer.__init__(self, reactor, port)

        self._handlers.update({
            # Allocate handlers
            (METHOD_ALLOCATE, stun.CLASS_REQUEST):
                self._stun_allocate_request,
            # Refresh handlers
            (METHOD_REFRESH, stun.CLASS_REQUEST):
                self._stun_refresh_request,
            # Send handlers
            (METHOD_SEND, stun.CLASS_INDICATION):
                self._stun_send_indication,
            })

    def _stun_allocate_request(self, msg, (host, port)):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6.2
        """
        #TODO: detect retransmission, skip to success response
        # 1. require request to be authenticated
        # 2. Check if the 5-tuple is currently in use
        # 3. Check REQUESTED-TRANSPORT attribute
        requested_transport = msg.get_attr(ATTR_REQUESTED_TRANSPORT)
        if not requested_transport:
            pass # TODO: reject with 400
        if requested_transport.protocol != TRANSPORT_UDP:
            pass # TODO: reject with 442
        # 4. handle DONT-FRAGMENT attribute
        # 5. Check RESERVATION-TOKEN attribute
        reservation_token = msg.get_attr(ATTR_RESERVATION_TOKEN)
        even_port = msg.get_attr(ATTR_EVEN_PORT)
        if reservation_token:
            if even_port:
                pass # TODO: reject with 400
            relay_addr = self.get_reserved_transport_address(reservation_token)
            # TODO: check that token is in range and has not expired
            # and that corresponding relayed address is still available
            # if token not valid, reject with 508
        # 7. reject with 486 if username allocation quota reached
        # 8. reject with 300 if we want to redirect to another server RFC5389
        # 6. Check EVEN-PORT
        else:
            relay_addr, token = self._allocate_relay_addr(even_port)

        # Determine initial time-to-expiry
        lifetime = msg.get_attr(ATTR_LIFETIME)
        if lifetime:
            time_to_expiry = max(self.default_lifetime, min(self.max_lifetime, lifetime.time_to_expiry))
        else:
            time_to_expiry = self.default_lifetime

        response = stun.Message.encode(METHOD_ALLOCATE,
                                       stun.CLASS_RESPONSE_SUCCESS,
                                       transaction_id=msg.transaction_id)

        response.add_attr(XorRelayedAddress, *relay_addr)
        if token:
            response.add_attr(ReservationToken, token)
        response.add_attr(Lifetime, time_to_expiry)
        family = stun.Address.aftof(self.transport.addressFamily)
        response.add_attr(stun.XorMappedAddress, family, port, host)

        self.transport.write(response, (host, port))

    def _allocate_relay_addr(self, even_port):
        """
        :param even_port: If True, the allocated addres port number will be even
        :param reserve: Wether to reserve the next port number and assign a token
                #TODO: find pair of port-numbers N, N+1 on same IP where
                #      N is even, set relayed transport addr with N and
                #      reserve N+1 for atleast 30s (until N released)
                #      and assign a token to that reservation
        """
        family = stun.Address.FAMILY_IPv4
        port = 0
        address = '0.0.0.0'
        return (family, port, address), None

    def _stun_refresh_request(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-7.2
        """
        pass

    def _stun_send_indication(self, msg, addr):
        pass

def main():
    from twisted.internet import reactor

#     addr = '23.251.129.121', 3478

    server = TurnUdpServer(reactor)
    addr = 'localhost', server.start()

    client = TurnUdpClient(reactor)
    client.start()

    d = client.allocate(addr)
    @d.addCallback
    def allocation_succeeded(allocation):
        print "*** Allocation succeeded:", allocation
    @d.addErrback
    def allocation_failed(failure):
        print "*** Allocation failed:", failure
    @d.addBoth
    def stop(result):
        reactor.stop()

    reactor.run()

if __name__ == '__main__':
    main()
