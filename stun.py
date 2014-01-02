from message import StunMessage, METHOD_BINDING, CLASS_REQUEST, MAGIC_COOKIE,\
    Software
from twisted.internet.protocol import DatagramProtocol
import os


class StunUdpClient(DatagramProtocol):
    SOFTWARE = "PexSTUN Agent"

    def __init__(self, retransmission_timeout=3., retransmission_continue=7, retransmission_m=16):
        self.retransmision_timeout = retransmission_timeout
        self.retransmission_continue = retransmission_continue
        self.message_buffer = bytearray()

    def request_BINDING(self, host, port, software=SOFTWARE):
        """
        :see: http://tools.ietf.org/html/rfc5389#section-7.1
        """
        attributes = []
        if software:
            attributes.append(Software.create(software))
        length = sum(len(attribute) for attribute in attributes)
        transaction_id = os.urandom(12)
        message = StunMessage(METHOD_BINDING, CLASS_REQUEST, length, MAGIC_COOKIE, transaction_id, attributes)
        self.transport.write(message.encode(), (host, port))

#     def datagramReceived(self, datagram, addr):
#         print repr(datagram)
#         self.message_buffer += datagram
#         offset = 0
#         while len(self.message_buffer) - offset > StunMessage._HEADER_SIZE:
#             offset += StunMessage._HEADER_SIZE
#             try:
#                 message = StunMessage.decode(self.message_buffer, offset)
#             except Exception as e:
#                 print "dropping", e, offset, hex(self.message_buffer[offset])
#                 self.message_buffer = bytearray()
#                 return
#             else:
#                 if message:
#                     offset += message.msg_length
#                     self.dispatchMessage(message)
#                     print message
#         self.message_buffer = self.message_buffer[offset:]

    def datagramReceived(self, datagram, addr):
        try:
            message = StunMessage.decode(datagram, 0)
        except:
            print "not stun message"
        else:
            print message
            if message:
                pass

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
            self.message_buffer = bytearray()
        return message

    def messageReceived(self, message):
        pass


class StunTCPClient(object):
    connection_timeout = 39.5

if __name__ == '__main__':
    from twisted.internet import reactor
    stun_client = StunUdpClient()
    port = reactor.listenUDP(0, stun_client)
    stun_client.request_BINDING('46.19.20.100', 3478, software='')
#     stun_client.request_BINDING('8.34.221.6', 3478)
#     stun_client.request_BINDING('localhost', 6666)
    reactor.callLater(5, reactor.stop)
    reactor.run()
