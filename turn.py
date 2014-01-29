import stun
import struct
from stun_agent import StunUdpClient, StunUdpServer, TransactionError,\
    LongTermCredentialMechanism, CredentialMechanism
from twisted.internet.protocol import DatagramProtocol

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
    _struct = struct.Struct('>L')

    def __init__(self, data, time_to_expiry):
        self.time_to_expiry = time_to_expiry

    @classmethod
    def decode(cls, data, offset, length):
        lifetime, = cls._struct.unpack_from(data, offset)
        return cls(buffer(data, offset, length), lifetime)

    @classmethod
    def encode(cls, msg, time_to_expiry):
        return cls(cls._struct.pack(time_to_expiry), time_to_expiry)

    def __repr__(self):
        return "LIFETIME(time-to-expiry={})".format(self.time_to_expiry)


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

    def __repr__(self):
        return "DATA(length={})".format(len(self))


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

    def __repr__(self, *args, **kwargs):
        return "REQUESTED-TRANSPORT({:#02x})".format(self.protocol)


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


class Relay(DatagramProtocol):
    relay_addr = (None, None, None)

    def __init__(self, addr):
        self.addr = addr

        # Authentication information
        self.hmac_key = None
        self.nonce = None

        self.time_to_expiry = 10 * 60
        self.permissions = []#('ipaddr', 'lifetime'),]
        self._channels = {} # channel to peer bindings


    @classmethod
    def allocate(cls, reactor, addr, interface, port=0):
        relay = cls(addr)
        port = reactor.listenUDP(port, relay, interface)
        family = stun.Address.aftof(relay.transport.socket.family)
        addr, port = relay.transport.socket.getsockname()
        relay.relay_addr = (family, port, addr)
        print "*** Started {}".format(relay)
        return relay

    def add_permission(self, peer_addr):
        self.permissions.append(peer_addr)

    def send(self, data, addr):
        print "*** {} -> {}:{}".format(self, *addr)
        host, port = addr
        if host in self.permissions:
            self.transport.write(data, addr)
        else:
            print "*** WARNING: No permissions for {}: Dropping Send request".format(host)
            print datagram.encode('hex')

    def datagramReceived(self, datagram, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-10.3
        """
        print "*** {} <- {}:{}".format(self, *addr)
        host, port = addr
        if host in self.permissions:
            channel = self._channels.get(addr)
            if channel:
                # TODO: send channel message to client
                raise NotImplementedError("Send channel message")
            else:
                msg = stun.Message.encode(METHOD_DATA,
                                          stun.CLASS_INDICATION)
                family = stun.Address.aftof(self.transport.addressFamily)
                msg.add_attr(XorPeerAddress, family, port, host)
                msg.add_attr(Data, datagram)
            self.transport.write(msg, self.addr)
        else:
            print "*** WARNING: No permissions for {}: Dropping datagram".format(host)
            print datagram.encode('hex')


    def __str__(self):
        return ("Relay(relay-addr={0[2]}:{0[1]}, client-addr={1[0]}:{1[1]})"
                .format(self.relay_addr, self.addr))


class Allocation(object):
    """Server side allocation
    """
    relay_transport_address = None

    transaction_id = None # For detecting retransmissions

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

    def get_hmac_key(self, realm):
        return stun.ha1('username', realm, 'password')


class Allocation_UnAllocated():
    def __init__(self, host, port, transport=TRANSPORT_UDP, time_to_expiry=None):
        self.auth = CredentialMechanism()

    def allocate(self):
        pass

    def _stun_allocate_error(self, response):
        error_code = response.get_attr(stun.ATTR_ERROR_CODE)
        realm = response.get_attr(stun.ATTR_REALM)
        nonce = response.get_attr(stun.ATTR_NONCE)
        if (error_code.code == stun.ERR_UNAUTHORIZED
            and realm != self.realm
            and nonce != self.nonce):
            # Unauthorized, and got new auth info
            hmac_key = self._get_hmac_key(realm)
            self.allocate()

    def _stun_allocation_succeess(self, response):
        self.state_data.relay_transport_address = response.get_attr(ATTR_XOR_RELAYED_ADDRESS)
        return Allocation_Allocated(self.state_data)

    def _get_hmac_key(self, realm):
        return stun.ha1('username', realm, 'password')

class Allocation_Allocated():
    def refresh(self, time_to_expiry):
        pass

    def delete(self):
        self.refresh(time_to_expiry=0)

    def _stun_refresh_error(self, reason):
        pass

    def _stun_refresh_success(self, result):
        pass

    def create_permission(self):
        pass

    def _stun_create_permission_error(self, response):
        pass

    def _stun_create_permission_success(self, response):
        pass

    def send(self):
        pass

    def _stun_data(self, indication):
        pass

    def channel_bind(self):
        pass

    def _stun_channel_bind_error(self, response):
        pass

    def _stun_channel_bind_success(self, response):
        pass


class TurnUdpClient(StunUdpClient):
    class UnAllocated():
        allocate = None

    class Allocating():
        _stun_allocate_success = None
        _stun_allocate_error = None

    class Allocated():
        refresh = None
        _stun_refresh_success = None
        _stun_refresh_error = None
        create_permission = None
        _stun_create_permission_success = None
        _stun_create_permission_error = None
        send = None
        _stun_data = None
        channel_bind = None
        _stun_channel_bind_success = None
        _stun_channel_bind_error = None

    class Expired(): pass

    def __init__(self, reactor):
        StunUdpClient.__init__(self, reactor)
        self.turn_server_domain_name = None
        self.allocation = None

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
        transaction = self.request(request, addr)
        transaction.addErrback
        def retry(failure):
            nonce = failure.value.get_attr(stun.ATTR_NONCE)
            realm = str(failure.value.get_attr(stun.ATTR_REALM))
            self.credential_mechanism = LongTermCredentialMechanism(nonce, realm, 'username', 'password')
            print self.credential_mechanism
            transaction.addCallback(lambda result: self.allocate(addr))

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
                transaction.fail(TransactionError("No allocation in response"))

    def _stun_allocate_error(self, msg, addr):
        transaction = self._transactions.get(msg.transaction_id)
        if transaction:
            error_code = msg.get_attr(stun.ATTR_ERROR_CODE)
            if not isinstance(self.credential_mechanism, LongTermCredentialMechanism):
                nonce = msg.get_attr(stun.ATTR_NONCE)
                realm = str(msg.get_attr(stun.ATTR_REALM))
                self.credential_mechanism = LongTermCredentialMechanism(nonce, realm, 'username', 'password')
                print self.credential_mechanism
                transaction.addCallback(lambda result: self.allocate(addr))
            else:
                transaction.fail(TransactionError(error_code))

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

    def __init__(self, reactor, username, password, realm, port=3478, interface=''):
        StunUdpServer.__init__(self, reactor, port, interface)
        self._relays = {}

        nonce = 'somerandomnonce'
        self.credential_mechanism = LongTermCredentialMechanism(nonce, realm, username, password)

        self._handlers.update({
            # Allocate handlers
            (METHOD_ALLOCATE, stun.CLASS_REQUEST):
                self._stun_allocate_request,
            # Refresh handlers
            (METHOD_REFRESH, stun.CLASS_REQUEST):
                self._stun_refresh_request,
            # Create permission handlers
            (METHOD_CREATE_PERMISSION, stun.CLASS_REQUEST):
                self._stun_create_permission_request,
            # Send handlers
            (METHOD_SEND, stun.CLASS_INDICATION):
                self._stun_send_indication,
            # ChannelBind handler
            (METHOD_CHANNEL_BIND, stun.CLASS_REQUEST):
                self._stun_channel_bind_request,
            })

    def _stun_allocate_request(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6.2
        """
        # Detect retransmission, resend success response
        relay_allocation = self._relays.get(addr)
        if relay_allocation and relay_allocation.transaction_id == msg.transaction_id:
            # TODO: handle allocate retransmission
            raise NotImplementedError("Allocation retransmission")

        # 1. require request to be authenticated
        message_integrity = msg.get_attr(stun.ATTR_MESSAGE_INTEGRITY)
        if not message_integrity:
            response = msg.create_response(stun.CLASS_RESPONSE_ERROR)
            response.add_attr(stun.ErrorCode, *stun.ERR_UNAUTHORIZED)
            self.respond(response, addr)
            return

        # 2. Check if the 5-tuple is currently in use
        if relay_allocation:
            response = msg.create_response(stun.CLASS_RESPONSE_ERROR)
            response.add_attr(stun.ErrorCode, *ERR_ALLOCATION_MISMATCH)
            self.respond(response, addr)
            return

        # 3. Check REQUESTED-TRANSPORT attribute
        requested_transport = msg.get_attr(ATTR_REQUESTED_TRANSPORT)
        if not requested_transport:
            response = msg.create_response(stun.CLASS_RESPONSE_ERROR)
            response.add_attr(stun.ErrorCode, *stun.ERR_BAD_REQUEST)
            self.respond(response, addr)
            return
        elif requested_transport.protocol != TRANSPORT_UDP:
            response = msg.create_response(stun.CLASS_RESPONSE_ERROR)
            response.add_attr(stun.ErrorCode, *ERR_UNSUPPORTED_TRANSPORT_PROTOCOL)
            self.respond(response, addr)
            return

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
            relay, token = self._allocate_relay_addr(even_port, addr)
            relay.transaction_id = msg.transaction_id
            relay_addr = relay.relay_addr

        # Determine initial time-to-expiry
        time_to_expiry = self._time_to_expiry(msg.get_attr(ATTR_LIFETIME))

        response = msg.create_response(stun.CLASS_RESPONSE_SUCCESS)
        response.add_attr(XorRelayedAddress, *relay_addr)
        if token:
            response.add_attr(ReservationToken, token)
        response.add_attr(Lifetime, time_to_expiry)
        family = stun.Address.aftof(self.transport.addressFamily)
        host, port = addr
        response.add_attr(stun.XorMappedAddress, family, port, host)

        self.respond(response, addr)

    def _allocate_relay_addr(self, even_port, addr):
        """
        :param even_port: If True, the allocated addres port number will be even
        :param even_port.reserve: Wether to reserve the next port number and assign a token
                #TODO: find pair of port-numbers N, N+1 on same IP where
                #      N is even, set relayed transport addr with N and
                #      reserve N+1 for atleast 30s (until N released)
                #      and assign a token to that reservation
        """
        if even_port:
            raise NotImplementedError("EVEN-PORT handling")
        relay = Relay.allocate(self.reactor, addr, self.interface)
        self._relays[addr] = relay
        return relay, None

    def _time_to_expiry(self, lifetime):
        if lifetime:
            time_to_expiry = max(self.default_lifetime, min(self.max_lifetime,lifetime.time_to_expiry))
        else:
            time_to_expiry = self.default_lifetime
        return time_to_expiry

    def _stun_refresh_request(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-7.2
        """
        lifetime = msg.get_attr(ATTR_LIFETIME)
        if lifetime and lifetime.time_to_expiry == 0:
            desired_lifetime = 0
        else:
            desired_lifetime = self._time_to_expiry(lifetime)

        if desired_lifetime:
            response = msg.create_response(stun.CLASS_RESPONSE_SUCCESS)
            response.add_attr(Lifetime, desired_lifetime)
            self.respond(response, addr)
        elif addr in self._relays:
            del self._relays[addr]

    def _stun_create_permission_request(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-9.2
        """
        # 1. require request to be authenticated
        message_integrity = msg.get_attr(stun.ATTR_MESSAGE_INTEGRITY)
        if not message_integrity:
            response = msg.create_response(stun.CLASS_RESPONSE_ERROR)
            response.add_attr(stun.ErrorCode, *stun.ERR_UNAUTHORIZED)
            self.respond(response, addr)
            return

        relay = self._relays[addr]
        peer_addr = msg.get_attr(ATTR_XOR_PEER_ADDRESS)
        relay.add_permission(peer_addr.address)
        response = msg.create_response(stun.CLASS_RESPONSE_SUCCESS)
        self.respond(response, addr)

    def _stun_send_indication(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-10.2
        """
        # TODO: [preliminary implementation]
        relay = self._relays[addr]
        peer_addr = msg.get_attr(ATTR_XOR_PEER_ADDRESS)
        data = msg.get_attr(ATTR_DATA)
        relay.send(data, (peer_addr.address, peer_addr.port))

    def _stun_channel_bind_request(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-11.2
        """
        raise NotImplementedError("ChannelBind request")


def main():
    from twisted.internet import reactor

    addr = '23.251.129.121', 3478

#     server = TurnUdpServer(reactor)
#     addr = 'localhost', server.start()

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
        pass #reactor.stop()

    reactor.run()


def runserver(interface, port, username, password, realm):
    """Usage: turn <interface> <port> <username> <password> <realm>
    """
    from twisted.internet import reactor
    server = TurnUdpServer(reactor, username, password, realm, port=int(port),
                           interface=interface)
    server.start()
    reactor.run()


if __name__ == '__main__':
    import sys
    runserver(*sys.argv[1:])
