from twisted.internet.protocol import DatagramProtocol


class RelayAllocation(DatagramProtocol):
    def __init__(self, reactor):
        self.reactor = reactor

        # Authentication information
        self.hmac_key = None
        self.nonce = None

        self.time_to_expiry = 10 * 60
        self.permissions = [('ipaddr', 'lifetime'),]
        self.channel_to_peer_bindings = []

    def start(self, interface, port=0):
        port = self.reactor.listenUDP(port, self, interface)
        print "*** Started {}".format(port), port.socket.getsockname(), port.port
        return port

    def datagramReceived(self, datagram, addr):
        print "*** {} Received datagram:".format(self), datagram.encode('hex')


def main(argv):
    relay = RelayAllocation()
    relay.start


if __name__ == '__main__':
    from sys import argv
    main(argv)
