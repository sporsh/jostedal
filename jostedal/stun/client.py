from twisted.internet import defer
from jostedal.stun.agent import StunUdpProtocol, Message
from jostedal.stun.authentication import CredentialMechanism
from jostedal import stun
from jostedal.stun import attributes
import logging


logger = logging.getLogger(__name__)


class StunUdpClient(StunUdpProtocol):
    def __init__(self, reactor, port=0):
        StunUdpProtocol.__init__(self, reactor, port)
        self._transactions = {}
        self.credential_mechanism = CredentialMechanism()

    def bind(self, addr):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.1
        """
        request = Message.encode(stun.METHOD_BINDING, stun.CLASS_REQUEST)
        request.add_attr(attributes.Software, self.software)
        return self.request(request, addr)

    def request(self, request, addr):
        """Send a STUN request
        """
        self.credential_mechanism.update(request)
        request.add_attr(attributes.Fingerprint)
        transaction = StunTransaction(request, addr)
        self._transactions[transaction.transaction_id] = transaction
        transaction.addBoth(self._transaction_completed, transaction)
        self.send(transaction, self.RTO, self.Rc)
        return transaction

    def send(self, transaction, rto, rc):
        """Send and handle retransmission of STUN transactions
        :param rto: Retransmission TimeOut
        :param rc: Retransmission count, maximum number of requests to send
        :see: http://tools.ietf.org/html/rfc5389#section-7.2.1
        """
        if not transaction.called:
            if rc:
                logger.info("%s Sending Request RTO=%d, Rc=%d", transaction, rto, rc)
                self.transport.write(transaction.request, transaction.addr)
                self.reactor.callLater(rto, self.send, transaction, rto*2, rc-1)
            else:
                logger.warning("%s Time Out in %ds", transaction, self.timeout)
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
