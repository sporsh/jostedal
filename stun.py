from message import StunMessage, METHOD_BINDING, CLASS_REQUEST, aftof, CLASS_RESPONSE_SUCCESS,\
    CLASS_RESPONSE_ERROR, UnknownAttributes, ATTRIBUTE_SOFTWARE,\
    ATTRIBUTE_XOR_MAPPED_ADDRESS
from twisted.internet.protocol import DatagramProtocol

AGENT_NAME = "PexSTUN Agent"


class StunBindingTransaction(object):
    def __init__(self):
        pass

    def handle_REQUEST(self, message, family, port, host):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.1
        """
        # 1. check unknown comprehension-required attributes
        #    - reply with 420

        attributes = []

        #error
        response_class = CLASS_RESPONSE_ERROR
        attributes.append(UnknownAttributes, ([],)) #TODO: list of unknown attrs in message

        #success
        attributes.append((ATTRIBUTE_XOR_MAPPED_ADDRESS, 0, (aftof(family), port, host)))
        response_class = CLASS_RESPONSE_SUCCESS

        response = StunMessage.encode(message.method,
                                      response_class,
                                      message.transaction_id,
                                      attributes=attributes)
        return response

    def handle_INDICATION(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.2
        """
        # 1. check unknown comprehension-required attributes
        #    - discard

    def handle_RESPONSE_SUCCESS(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.3
        """
        # 0. check unknown comprehension-required (fail trans if present)
        # 1. check xor-mapped-address is present
        # 2. check address family (ignore if unknown, may accept IPv6 when sent IPv4)

    def handle_RESPONSE_ERROR(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.4
        """
        # 1. unknown comp-req or no ERROR-CODE: transaction simply failed
        # 2. authentication provcessing (sec. 10)
        # error code 300 -> 399; SHOULD fail unless ALTERNATE-SERVER (sec 11)
        # error code 400 -> 499; transaction failed (420, UNKNOWN ATTRIBUTES contain info)
        # error code 500 -> 599; MAY resend, but MUST limit number of retries


class StunAuthTransaction(object):
    pass


class StunUdpProtocol(DatagramProtocol):

    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        self.retransmision_timeout = retransmission_timeout
        self.retransmission_continue = retransmission_continue

    def datagramReceived(self, datagram, (host, port)):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3
        """
        # 1. check that the two first bytes are 0b00
        # 2. check magic cookie
        # 3. check sensible message length
        # 4. check method is supported
        # 4. check that class is allowed for method

        try:
            message = StunMessage.decode(datagram, 0)
        except Exception as e:
            print "Failed to decode datagram:", e
        else:
            if message:
                self.messageReceived(message, (self.transport.addressFamily, port, host))

    def messageReceived(self, message, addr):
        """
        """
        # dispatch message to correct transaction
        print message, addr

    def stun_RESPONSE(self):
        # 1. check transaction id match active transaction
        # 2. if FINGERPRINT, check that it contain correct value
        pass


class StunUdpClient(StunUdpProtocol):
    def request_BINDING(self, host, port, software=AGENT_NAME):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.1
        """
        attributes = []
        if software:
            attributes.append((ATTRIBUTE_SOFTWARE, 0, software))
        message = StunMessage(METHOD_BINDING, CLASS_REQUEST,
                              attributes=attributes)
        print repr(message)
        self.transport.write(message.encode(), (host, port))


class StunUdpServer(StunUdpProtocol):
    pass


class StunTCPClient(object):
    connection_timeout = 39.5


if __name__ == '__main__':
    from twisted.internet import reactor
    stun_client = StunUdpClient()
    port = reactor.listenUDP(0, stun_client)
    stun_client.request_BINDING('46.19.20.100', 3478)
#     stun_client.request_BINDING('8.34.221.6', 3478)

#     stun_client.request_BINDING('localhost', 6666)
    reactor.callLater(5, reactor.stop)
    reactor.run()
