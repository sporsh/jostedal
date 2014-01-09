from twisted.internet.protocol import DatagramProtocol
from pexice.rfc5389_attributes import ATTRIBUTE_ERROR_CODE
from message import CLASS_INDICATION, CLASS_RESPONSE_SUCCESS,\
    CLASS_RESPONSE_ERROR, Message, METHOD_BINDING, ATTR_SOFTWARE,\
    ATTR_FINGERPRINT, CLASS_REQUEST, ATTR_UNKNOWN_ATTRIBUTES,\
    ATTR_XOR_MAPPED_ADDRESS, Address

AGENT_NAME = "PexICE-0.1.0 'Jostedal'"


class StunBindingTransaction(object):
    _HANDLERS = {CLASS_INDICATION: 'handle_INDICATION',
                 CLASS_RESPONSE_SUCCESS: 'handle_RESPONSE_SUCCESS',
                 CLASS_RESPONSE_ERROR: 'handle_RESPONSE_ERROR'}

    def __init__(self, agent, request):
        self.agent = agent
        self.messages = [request]

    def messageReceived(self, msg, addr):
        handler_name = self._HANDLERS.get(msg.msg_class)
        handler = getattr(self, handler_name)
        handler(msg)

    def handle_INDICATION(self, message):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.2
        """
        # 1. check unknown comprehension-required attributes
        #    - discard

    def handle_RESPONSE_SUCCESS(self, msg):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.3
        """
        # 0. check unknown comprehension-required (fail trans if present)
        unknown_attributes = msg.unknown_required_attributes()
        if unknown_attributes:
            #TODO: notify user about failure in success response
            print "*** ERROR: Unknown comp-required attributes in response", repr(unknown_attributes)
            return
        # 1. check that XOR-MAPPED-ADDRESS is present
        # 2. check address family (ignore if unknown, may accept IPv6 when sent IPv4)

        print "*** TRANSACTION SUCCEEDED"

    def handle_RESPONSE_ERROR(self, msg):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.4
        """
        # 1. unknown comp-req or no ERROR-CODE: transaction simply failed
        # 2. authentication provcessing (sec. 10)
        # error code 300 -> 399; SHOULD fail unless ALTERNATE-SERVER (sec 11)
        # error code 400 -> 499; transaction failed (420, UNKNOWN ATTRIBUTES contain info)
        # error code 500 -> 599; MAY resend, but MUST limit number of retries

        #TODO: notify user about failure
        print "*** TRANSACTION FAILED"


class StunAuthTransaction(object):
    pass


class StunUdpProtocol(DatagramProtocol):
    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        self.retransmision_timeout = retransmission_timeout
        self.retransmission_continue = retransmission_continue

    def datagramReceived(self, datagram, addr):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3
        """
        # 1. check that the two first bytes are 0b00
        # 2. check magic cookie
        # 3. check sensible message length
        # 4. check method is supported
        # 4. check that class is allowed for method

        try:
            msg = Message.decode(datagram)
        except Exception as e:
            print "Failed to decode datagram:", e
        else:
            if msg:
                print "*** RECEIVED", msg.format()
                self.dispatchMessage(msg, addr)



class StunUdpClient(StunUdpProtocol):
    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        StunUdpProtocol.__init__(self, retransmission_timeout=retransmission_timeout,
                                 retransmission_continue=retransmission_continue,
                                 retransmission_m=retransmission_m)
        self.transactions = {}

    def request_BINDING(self, host, port, software=AGENT_NAME):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.1
        """
        msg = Message.encode(METHOD_BINDING, CLASS_REQUEST)
        msg.add_attribute(ATTR_SOFTWARE, software)
        msg.add_attribute(ATTR_FINGERPRINT)
        self.transactions[msg.transaction_id] = StunBindingTransaction(self, msg)
        print "*** SENDING", msg.format()
        self.transport.write(msg, (host, port))

    def dispatchMessage(self, msg, addr):
                # Dispatch message to transaction
                transaction = self.transactions.get(msg.transaction_id)
                if transaction:
                    transaction.messageReceived(msg, addr)
                else:
                    print "*** NO SUCH TRANSACTION", msg.transaction_id.encode('hex')


class StunUdpServer(StunUdpProtocol):
    _HANDLERS = {CLASS_REQUEST: 'handle_REQUEST',
                 }

    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        StunUdpProtocol.__init__(self, retransmission_timeout=retransmission_timeout, retransmission_continue=retransmission_continue, retransmission_m=retransmission_m)

    def dispatchMessage(self, message, addr):
        handler_name = self._HANDLERS.get(message.msg_class)
        handler = getattr(self, handler_name)
        handler(message, addr)

    def handle_REQUEST(self, message, (host, port)):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.1
        """
        attributes = [(ATTR_SOFTWARE, 0, AGENT_NAME)]
        # 1. check unknown comprehension-required attributes
        unknown_attributes = message.get_unknown_attributes()
        if unknown_attributes:
            #error
            #    - reply with 420
            response_class = CLASS_RESPONSE_ERROR
            attributes.append((ATTRIBUTE_ERROR_CODE, 0, (4, 20, "Unknown comprehension-required attributes")))
            unknown_attr_types = [attr.type for attr in unknown_attributes]
            attributes.append((ATTR_UNKNOWN_ATTRIBUTES, 0, unknown_attr_types))
        else:
            #success
            family = Address.aftof(self.transport.addressFamily)
            attributes.append((ATTR_XOR_MAPPED_ADDRESS, 0, (family, port, host)))
            response_class = CLASS_RESPONSE_SUCCESS

        attributes.append((ATTR_FINGERPRINT, 0, 0))
        response = Message(message.msg_method,
                               response_class,
                               transaction_id=message.transaction_id,
                               attributes=attributes)
        self.transport.write(response.encode(), (host, port))


class StunTCPClient(object):
    connection_timeout = 39.5


if __name__ == '__main__':
    from twisted.internet import reactor


#     stun_server = StunUdpServer()
#     port = reactor.listenUDP(6666, stun_server)


    stun_client = StunUdpClient()
    port = reactor.listenUDP(0, stun_client)
#     stun_client.request_BINDING('localhost', 6666)
    stun_client.request_BINDING('23.251.129.121', 3478)
#     stun_client.request_BINDING('46.19.20.100', 3478)
#     stun_client.request_BINDING('8.34.221.6', 3478)
#     stun_client.request_BINDING('localhost', 6666)

    reactor.callLater(5, reactor.stop)
    reactor.run()
