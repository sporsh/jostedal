from twisted.internet.protocol import DatagramProtocol
from jostedal.stun.agent import Address, Message
import logging
from jostedal import stun, turn
from jostedal.turn import attributes


logger = logging.getLogger(__name__)


class Relay(DatagramProtocol):
    relay_addr = (None, None, None)

    def __init__(self, server, client_addr):
        self.server = server
        self.client_addr = client_addr

        # Authentication information
        self.hmac_key = None
        self.nonce = None

        self.time_to_expiry = 10 * 60
        self.permissions = []#('ipaddr', 'lifetime'),]
        self._channels = {} # channel to peer bindings


    @classmethod
    def allocate(cls, server, client_addr, port=0):
        relay = cls(server, client_addr)
        port = server.reactor.listenUDP(port, relay, server.interface)
        family = Address.aftof(relay.transport.socket.family)
        relay_ip, port = relay.transport.socket.getsockname()
        relay.relay_addr = (family, port, relay_ip)
        logger.info("%s Allocated", relay)
        return relay

    def add_permission(self, peer_addr):
        logger.info("%s Added permission for %s", self, peer_addr)
        self.permissions.append(peer_addr)

    def send(self, data, addr):
        logger.info("%s -> %s:%d", self, *addr)
        host, _port = addr
        if host in self.permissions:
            self.transport.write(data, addr)
        else:
            logger.warning("No permissions for %s: Dropping Send request", host)
            logger.debug(data.encode('hex'))

    def datagramReceived(self, datagram, addr):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-10.3
        """
        logger.info("%s <- %s:%d", self, *addr)
        host, port = addr
        if host in self.permissions:
            channel = self._channels.get(addr)
            if channel:
                # TODO: send channel message to client
                raise NotImplementedError("Send channel message")
            else:
                msg = Message.encode(turn.METHOD_DATA,
                                     stun.CLASS_INDICATION)
                family = Address.aftof(self.transport.addressFamily)
                msg.add_attr(attributes.XorPeerAddress, family, port, host)
                msg.add_attr(attributes.Data, datagram)
            self.server.transport.write(msg, self.client_addr)
        else:
            logger.warning("No permissions for %s: Dropping datagram", host)
            logger.debug(datagram.encode('hex'))


    def __str__(self):
        return ("Relay(relay-addr={0[2]}:{0[1]}, client-addr={1[0]}:{1[1]})"
                .format(self.relay_addr, self.client_addr))
