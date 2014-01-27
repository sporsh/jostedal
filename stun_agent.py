import stun
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import defer


AGENT_NAME = "PexICE-0.1.0 'Jostedal'"


class TransactionError(Exception):
    pass


class StunTransaction(defer.Deferred):
    fail = defer.Deferred.errback
    succeed = defer.Deferred.callback

    def __init__(self, request, addr):
        defer.Deferred.__init__(self)
        self.transaction_id = request.transaction_id
        self.request = request
        self.addr = addr

    def time_out(self):
        if not self.called:
            self.fail(TransactionError("Timed out"))


class StunUdpProtocol(DatagramProtocol):
    software = AGENT_NAME

    def __init__(self, reactor, port, interface='', RTO=3., Rc=7, Rm=16):
        """
        :param port: UDP port to bind to
        :param RTO: Retransmission TimeOut (initial value)
        :param Rc: Retransmission Count (maximum number of request to send)
        :param Rm: Retransmission Multiplier (timeout = Rm * RTO)
        """
        self.reactor = reactor
        self.port = port
        self.interface = interface
        self.RTO = .5
        self.Rc = 7
        self.timeout = Rm * RTO

        self._handlers = {
            # Binding handlers
            (stun.METHOD_BINDING, stun.CLASS_REQUEST):
                self._stun_binding_request,
            (stun.METHOD_BINDING, stun.CLASS_INDICATION):
                self._stun_binding_indication,
            (stun.METHOD_BINDING, stun.CLASS_RESPONSE_SUCCESS):
                self._stun_binding_success,
            (stun.METHOD_BINDING, stun.CLASS_RESPONSE_ERROR):
                self._stun_binding_error,
            }

    def start(self):
        port = self.reactor.listenUDP(self.port, self, self.interface)
        print "*** Started {}".format(port)
        return port.port

    def datagramReceived(self, datagram, addr):
        try:
            msg = stun.Message.decode(datagram)
        except Exception as e:
            print "Failed to decode datagram:", e
            raise
        else:
            if isinstance(msg, stun.Message):
                self._stun_received(msg, addr)

    def _stun_received(self, msg, addr):
        handler = self._handlers.get((msg.msg_method, msg.msg_class))
        if handler:
            print "*** {} Received STUN".format(self)
            print msg.format()
            handler(msg, addr)
        else:
            print "*** {} Received unrecognized STUN".format(self)
            print msg.format()

    def _stun_unhandeled(self, msg, addr):
        print "*** {} Unhandeled message from {}".format(self, addr)
        print msg.format()

    def _stun_binding_request(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_indication(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_success(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_error(self, msg, addr):
        self._stun_unhandeled(msg, addr)


class StunUdpClient(StunUdpProtocol):
    def __init__(self, reactor, port=0):
        StunUdpProtocol.__init__(self, reactor, port)
        self._transactions = {}
        self.credential_mechanism = CredentialMechanism()

    def bind(self, addr):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.1
        """
        request = stun.Message.encode(stun.METHOD_BINDING, stun.CLASS_REQUEST)
        request.add_attr(stun.Software, self.software)
        return self.request(request, addr)

    def request(self, request, addr):
        self.credential_mechanism.update(request)
        request.add_attr(stun.Fingerprint)
        transaction = StunTransaction(request, addr)
        self._transactions[transaction.transaction_id] = transaction
        transaction.addBoth(self._transaction_completed, transaction)
        self.send(transaction, self.RTO, self.Rc)
        print request.format()
        return transaction

    def send(self, transaction, rto, rc):
        """Send and handle retransmission of STUN transactions
        :param rto: Retransmission TimeOut
        :param rc: Retransmission count, maximum number of requests to send
        :see: http://tools.ietf.org/html/rfc5389#section-7.2.1
        """
        if not transaction.called:
            if rc:
                print "*** {} Sending Request RTO={}, Rc={}".format(transaction, rto, rc)
                self.transport.write(transaction.request, transaction.addr)
                self.reactor.callLater(rto, self.send, transaction, rto*2, rc-1)
            else:
                print "***", transaction, "Time Out in {}s".format(self.timeout)
                self.reactor.callLater(self.timeout, transaction.time_out)

    def _transaction_completed(self, result, transaction):
        del self._transactions[transaction.transaction_id]
        return result

    def get_transaction(self, msg):
        return self._transactions.get(msg.transaction_id)

    def _stun_binding_success(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.3
        """
        transaction = self._transactions.get(msg.transaction_id)
        if transaction:
            address = msg.get_attr(stun.ATTR_XOR_MAPPED_ADDRESS, stun.ATTR_MAPPED_ADDRESS)
            if address:
                transaction.succeed(str(address))
            else:
                transaction.fail(TransactionError("No Mapped Address in response", msg))

    def _stun_binding_error(self, msg, addr):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.3.4
        """
        transaction = self._transactions.get(msg.transaction_id)
        if transaction:
        # 2. authentication processing (sec. 10)
        # error code 300 -> 399; SHOULD fail unless ALTERNATE-SERVER (sec 11)
        # error code 400 -> 499; transaction failed (420, UNKNOWN ATTRIBUTES contain info)
        # error code 500 -> 599; MAY resend, but MUST limit number of retries
            transaction.fail(TransactionError(msg))


class StunUdpServer(StunUdpProtocol):
    def __init__(self, reactor, port=3478, interface=''):
        StunUdpProtocol.__init__(self, reactor, port, interface)

    def respond(self, response, addr):
        response.add_attr(stun.Software, self.software)
        self.credential_mechanism.update(response)
        response.add_attr(stun.Fingerprint)
        self.transport.write(response, addr)
        print "*** {} Sent".format(self)
        print response.format()

    def _stun_binding_request(self, msg, (host, port)):
        if msg.msg_class == stun.CLASS_REQUEST:
            unknown_attributes = msg.unknown_comp_required_attrs()
            if unknown_attributes:
                response = stun.Message.encode(stun.METHOD_BINDING,
                                               stun.CLASS_RESPONSE_ERROR,
                                               transaction_id=msg.transaction_id)
                response.add_attr(stun.ErrorCode, *stun.ERR_UNKNOWN_ATTRIBUTE)
                response.add_attr(stun.UnknownAttributes, unknown_attributes)
            else:
                response = stun.Message.encode(stun.METHOD_BINDING,
                                               stun.CLASS_RESPONSE_SUCCESS,
                                               transaction_id=msg.transaction_id)
                family = stun.Address.aftof(self.transport.addressFamily)
                response.add_attr(stun.XorMappedAddress, family, port, host)
                response.add_attr(stun.Software, AGENT_NAME)
                response.add_attr(stun.Fingerprint)
            self.respond(response, (host, port))

    def _stun_binding_indication(self, msg, addr):
        pass


class CredentialMechanism(object):
    def update(self, message):
        pass


class ShortTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.1
    """
    def __init__(self, username, password):
        self.username = username
        self.hmac_key = stun.saslprep(password)

    def update(self, msg):
        msg.add_attr(stun.Username, self.username)
        msg.add_attr(stun.MessageIntegrity, self.hmac_key)


class LongTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.2
    """
    def __init__(self, nonce, realm, username, password):
        self.nonce = nonce
        self.realm = realm
        self.hmac_key = stun.ha1(username, realm, password)

    def update(self, msg):
        msg.add_attr(stun.Nonce, self.nonce)
        msg.add_attr(stun.Realm, self.realm)
        msg.add_attr(stun.MessageIntegrity, self.hmac_key)

    def __str__(self):
        return "nonce={}, realm={}, hmac_key={}".format(self.nonce, self.realm, self.hmac_key)


def main():
    from twisted.internet import reactor

#     addr = '23.251.129.121', 3478
#     addr = '46.19.20.100', 3478
#     addr = '8.34.221.6', 3478

    server = StunUdpServer(reactor)
    addr = 'localhost', server.start()
#     addr = 'localhost', 666

    client = StunUdpClient(reactor)
    client.start()

    d = client.bind(addr)
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
