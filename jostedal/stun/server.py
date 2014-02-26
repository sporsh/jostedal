import logging
from jostedal.stun.agent import StunUdpProtocol
from jostedal.stun import attributes
from jostedal import stun
from jostedal.stun.agent import Message, Address
logger = logging.getLogger(__name__)


class StunUdpServer(StunUdpProtocol):
    def __init__(self, reactor, interface, port, software):
        StunUdpProtocol.__init__(self, reactor, interface, port, software)

    def respond(self, response, addr):
        response.add_attr(attributes.Software, self.software)
        self.credential_mechanism.update(response)
        response.add_attr(attributes.Fingerprint)
        self.transport.write(response, addr)
        logger.info("%s Sending response", self)
        logger.debug(response.format())

    def _stun_binding_request(self, msg, (host, port)):
        if msg.msg_class == stun.CLASS_REQUEST:
            unknown_attributes = msg.unknown_comp_required_attrs()
            if unknown_attributes:
                response = Message.encode(stun.METHOD_BINDING,
                                               stun.CLASS_RESPONSE_ERROR,
                                               transaction_id=msg.transaction_id)
                response.add_attr(attributes.ErrorCode, *stun.ERR_UNKNOWN_ATTRIBUTE)
                response.add_attr(attributes.UnknownAttributes, unknown_attributes)
            else:
                response = Message.encode(stun.METHOD_BINDING,
                                               stun.CLASS_RESPONSE_SUCCESS,
                                               transaction_id=msg.transaction_id)
                family = Address.aftof(self.transport.addressFamily)
                response.add_attr(attributes.XorMappedAddress, family, port, host)
                response.add_attr(attributes.Software, self.software)
                response.add_attr(attributes.Fingerprint)
            self.respond(response, (host, port))

    def _stun_binding_indication(self, msg, addr):
        pass
