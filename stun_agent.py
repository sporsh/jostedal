import stun
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import defer


AGENT_NAME = "PexICE-0.1.0 'Jostedal'"


class TransactionError(Exception):
    pass


class BindingTransaction(defer.Deferred):
    fail = defer.Deferred.errback
    succeed = defer.Deferred.callback

    def __init__(self, agent):
        defer.Deferred.__init__(self)
        request = stun.Message.encode(stun.METHOD_BINDING, stun.CLASS_REQUEST)
        request.add_attribute(stun.Software, agent.software)
        request.add_attribute(stun.Fingerprint)

        self.agent = agent
        self.transaction_id = request.transaction_id
        self.request = request

    def message_received(self, msg, addr):
        if msg.msg_method != stun.METHOD_BINDING:
            # TODO: shoud transaction fail at this point?
            return

        if msg.msg_class == stun.CLASS_INDICATION:
            pass
        elif msg.msg_class == stun.CLASS_RESPONSE_ERROR:
            # 1. unknown comp-req or no ERROR-CODE: transaction simply failed
            # 2. authentication provcessing (sec. 10)
            # error code 300 -> 399; SHOULD fail unless ALTERNATE-SERVER (sec 11)
            # error code 400 -> 499; transaction failed (420, UNKNOWN ATTRIBUTES contain info)
            # error code 500 -> 599; MAY resend, but MUST limit number of retries
            self.fail(TransactionError(msg))
        elif msg.msg_class == stun.CLASS_RESPONSE_SUCCESS:
            # 1. check that XOR-MAPPED-ADDRESS is present
            # 2. check address family (ignore if unknown, may accept IPv6 when sent IPv4)
            self.succeed(msg)


class StunUdpProtocol(DatagramProtocol):
    software = AGENT_NAME

    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        self.retransmision_timeout = retransmission_timeout
        self.retransmission_continue = retransmission_continue

    def start(self):
        from twisted.internet import reactor
        port = reactor.listenUDP(self.PORT, self)
        return port.port

    def datagramReceived(self, datagram, addr):
        try:
            msg = stun.Message.decode(datagram)
        except Exception as e:
            print "Failed to decode datagram:", e
            raise
        else:
            if isinstance(msg, stun.Message):
                print "*** Received STUN", msg.format()
                self.stun_message_received(msg, addr)


class StunUdpClient(StunUdpProtocol):
    PORT = 0

    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        StunUdpProtocol.__init__(self, retransmission_timeout=retransmission_timeout,
                                 retransmission_continue=retransmission_continue,
                                 retransmission_m=retransmission_m)
        self._transactions = {}

    def bind(self, host, port):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.1
        """
        transaction = BindingTransaction(self)
        self.transport.write(transaction.request, (host, port))
        self._transactions[transaction.transaction_id] = transaction
        transaction.addBoth(self.transaction_completed, transaction)
        return transaction

    def transaction_completed(self, result, transaction):
        del self._transactions[transaction.transaction_id]
        return result

    def stun_message_received(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.2 - 7.3.4
        """
        transaction = self._transactions.get(msg.transaction_id)
        if transaction:
            unknown_attributes = msg.unknown_comp_required_attrs(stun.IGNORED_ATTRS)
            if unknown_attributes:
                transaction.fail(TransactionError("Response contains unknown "
                    "comprehension-required attributes", unknown_attributes))
            else:
                transaction.message_received(msg, addr)
        else:
            print "*** NO SUCH TRANSACTION", msg.transaction_id.encode('hex')


class StunUdpServer(StunUdpProtocol):
    PORT = 3478
    _HANDLERS = {stun.CLASS_REQUEST: 'handle_REQUEST',
                 }

    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        StunUdpProtocol.__init__(self, retransmission_timeout=retransmission_timeout, retransmission_continue=retransmission_continue, retransmission_m=retransmission_m)

    def stun_message_received(self, msg, (host, port)):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.1
        """
        if msg.msg_class == stun.CLASS_REQUEST:
            unknown_attributes = msg.unknown_comp_required_attrs()
            if unknown_attributes:
                response = stun.Message.encode(stun.METHOD_BINDING,
                                               stun.CLASS_RESPONSE_ERROR,
                                               transaction_id=msg.transaction_id)
                response.add_attribute(stun.ErrorCode, *stun.ERR_UNKNOWN_ATTRIBUTE)
                response.add_attribute(stun.UnknownAttributes, unknown_attributes)
            else:
                response = stun.Message.encode(stun.METHOD_BINDING,
                                               stun.CLASS_RESPONSE_SUCCESS,
                                               transaction_id=msg.transaction_id)
                family = stun.Address.aftof(self.transport.addressFamily)
                response.add_attribute(stun.XorMappedAddress, family, port, host)

            response.add_attribute(stun.Software, AGENT_NAME)
            response.add_attribute(stun.Fingerprint)
            self.transport.write(response, (host, port))




def main():
    from twisted.internet import reactor

#     host, port = '23.251.129.121', 3478
#     host, port = '46.19.20.100', 3478
#     host, port = '8.34.221.6', 3478

    server = StunUdpServer()
    host, port = 'localhost', server.start()

    client = StunUdpClient()
    client.start()

    d = client.bind(host, port)
    @d.addCallback
    def binding_succeeded(binding):
        print "*** Binding succeeded:", binding.format()
    @d.addErrback
    def binding_failed(failure):
        print "*** Binding failed:", failure
    @d.addBoth
    def stop(result):
        reactor.stop()

    reactor.run()

if __name__ == '__main__':
    main()
