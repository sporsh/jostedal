from message import StunMessage, METHOD_BINDING, CLASS_REQUEST, MAGIC_COOKIE,\
    Software
from twisted.internet.protocol import DatagramProtocol


class StunUdpClient(DatagramProtocol):
    SOFTWARE = "PexSTUN Agent"

    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        self.retransmision_timeout = retransmission_timeout
        self.retransmission_continue = retransmission_continue

    def request_BINDING(self, software=SOFTWARE):
        attributes = []
        if software:
            attributes.append(Software(self.software))
        message = StunMessage(METHOD_BINDING, CLASS_REQUEST, length, MAGIC_COOKIE, transaction_id, attributes)

    def datagramReceived(self, datagram, addr):
        self.message_buffer += datagram
        offset = 0
        while len(self.message_buffer) - offset > StunMessage._HEADER_SIZE:
            offset += StunMessage._HEADER_SIZE
            message = StunMessage.decode(self.message_buffer, offset)
            if message:
                offset += message.msg_length
                self.dispatchMessage(message)
        self.message_buffer = self.message_buffer[offset:]

    def popMessage(self):
        """Get a message from the message_buffer and remove parsed data
        """
        message = None
        try:
            message = StunMessage.decode(self.message_buffer)
            message.validate(self.transaction_ids)
        except Exception as e:
            # In case of corrupt or invalid message, discard the buffer
            print e
            self.message_buffer = ''
        return message

    def messageReceived(self, message):
        pass

class StunTCPClient(object):
    connection_timeout = 39.5

if __name__ == '__main__':
    from twisted.internet import reactor
    from twisted.internet.protocol import ClientFactory
    from twisted.internet.endpoints import clientFromString
    factory = ClientFactory()
    factory.protocol = StunUdpClient
    endpoint = clientFromString(reactor, "udp:10.0.0.204:5555:timeout=5")
    client_d = endpoint.connect(factory)
    @client_d.addCallback
    def connection_made(client):
        print client
    @client_d.addErrback
    def connection_failed(reason):
        print reason

    reactor.run()
