import stun
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import defer, reactor


AGENT_NAME = "PexICE-0.1.0 'Jostedal'"


class TransactionError(Exception):
    pass


class BindingTransaction(defer.Deferred):
    fail = defer.Deferred.errback
    succeed = defer.Deferred.callback

    def __init__(self, agent, addr):
        defer.Deferred.__init__(self)
        request = stun.Message.encode(stun.METHOD_BINDING, stun.CLASS_REQUEST)
        request.add_attr(stun.Software, agent.software)
        agent.credential_mechanism.update(request)
        request.add_attr(stun.Fingerprint)

        self.addr = addr
        self.transaction_id = request.transaction_id
        self.request = request

    def time_out(self):
        if not self.called:
            self.fail(TransactionError("Timed out"))

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
            address = msg.get_attr(stun.XorMappedAddress) or msg.get_attr(stun.MappedAddress)
            if address:
                self.succeed(str(address))
            else:
                self.fail(TransactionError("No Mapped Address in response", msg))


class StunUdpProtocol(DatagramProtocol):
    software = AGENT_NAME
    RTO = .5#3. # retransmission_timeout
    Rc = 7 # retransmission_continue
    Rm = 16
    timeout = Rm * RTO

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

    def __init__(self):
        self._transactions = {}
        self.credential_mechanism = CredentialMechanism()

    def bind(self, host, port):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.1
        """
        transaction = BindingTransaction(self, (host, port))
        self._transactions[transaction.transaction_id] = transaction
        transaction.addBoth(self.transaction_completed, transaction)
        self.send(transaction, self.RTO, self.Rc)
        return transaction

    def send(self, transaction, rto, rc):
        """Handle UDP retransmission
        :param rto: Retransmission TimeOut
        :param rc: Retransmission count, maximum number of requests to send
        :see: http://tools.ietf.org/html/rfc5389#section-7.2.1
        """
        if not transaction.called:
            if rc:
                print "***", transaction, "Sending Request"
                self.transport.write(transaction.request, transaction.addr)
                reactor.callLater(rto, self.send, transaction, rto*2, rc-1)
            else:
                print "***", transaction, "Time Out in {}s".format(self.timeout)
                reactor.callLater(self.timeout, transaction.time_out)

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

    def send(self, msg, addr):
        self.transport.write(msg, addr)

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
            self.send(response, (host, port))


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


def main():
    from twisted.internet import reactor

#     host, port = '23.251.129.121', 3478
#     host, port = '46.19.20.100', 3478
#     host, port = '8.34.221.6', 3478

    server = StunUdpServer()
    host, port = 'localhost', server.start()
#     host, port = 'localhost', 666

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
