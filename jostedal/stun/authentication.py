from jostedal.utils import saslprep, ha1
from jostedal.stun import attributes


class CredentialMechanism(object):
    def update(self, message):
        pass


class ShortTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.1
    """
    def __init__(self, username, password):
        self.username = username
        self.hmac_key = saslprep(password)

    def update(self, msg):
        msg.add_attr(attributes.Username, self.username)
        msg.add_attr(attributes.MessageIntegrity, self.hmac_key)


class LongTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.2
    """
    def __init__(self, nonce, realm, username, password):
        self.nonce = nonce
        self.realm = realm
        self.hmac_key = ha1(username, realm, password)

    def update(self, msg):
        msg.add_attr(attributes.Nonce, self.nonce)
        msg.add_attr(attributes.Realm, self.realm)
        msg.add_attr(attributes.MessageIntegrity, self.hmac_key)

    def __str__(self):
        return "nonce={}, realm={}, hmac_key={}".format(self.nonce, self.realm, self.hmac_key)
