import unittest
from jostedal import stun
from jostedal.stun import Message

class MessageTest(unittest.TestCase):
    def setUp(self):
        msg_data = (
            '011300602112a442fedcb2d51f23946d'
            '9cc9754e0009001000000401556e6175'
            '74686f72697365640015001036303332'
            '3763313731343561373738380014000a'
            '7765627274632e6f72678e4f8022001a'
            '4369747269782d312e382e372e302027'
            '426c61636b20446f77270004'
            '802800045a4c0c70' # Fingerprint
            ).decode('hex')
        self.msg = Message.decode(msg_data)

    def test_decode(self):
        error_code = self.msg.get_attr(stun.ATTR_ERROR_CODE)
        self.assertEqual(error_code.code, 401)
        self.assertEqual(error_code.reason, u'Unauthorised')

        nonce = self.msg.get_attr(stun.ATTR_NONCE)
        self.assertEqual(nonce, '60327c17145a7788')

        realm = self.msg.get_attr(stun.ATTR_REALM)
        self.assertEqual(realm, 'webrtc.org')

        software = self.msg.get_attr(stun.ATTR_SOFTWARE)
        self.assertEqual(software, "Citrix-1.8.7.0 'Black Dow'")

        fingerprint = self.msg.get_attr(stun.ATTR_FINGERPRINT)
        self.assertEqual(fingerprint, '5a4c0c70'.decode('hex'))

    def test_encode(self):
        msg = Message.encode(stun.METHOD_BINDING,
                             stun.CLASS_REQUEST,
                             transaction_id='fixedtransid')
        # Override padding generation to make the message data deterministic
        msg._padding = '\x00'.__mul__ # Pad with zero bytes

        msg.add_attr(type('Foo', (stun.Unknown,), {'type': 0x6666}), 'data')
        msg.add_attr(stun.MappedAddress, stun.Address.FAMILY_IPv4, 1337, '192.168.2.255')
        msg.add_attr(stun.Username, "johndoe")
        msg.add_attr(stun.MessageIntegrity, stun.ha1('username', 'realm', 'password'))
        msg.add_attr(stun.ErrorCode, *stun.ERR_SERVER_ERROR)
        msg.add_attr(stun.UnknownAttributes, [0x1337, 0xb00b, 0xbeef])
        msg.add_attr(stun.Realm, "pexip.com")
        msg.add_attr(stun.Nonce, '36303332376331373134356137373838'.decode('hex'))
        msg.add_attr(stun.XorMappedAddress, stun.Address.FAMILY_IPv4, 1337, '192.168.2.255')
        msg.add_attr(stun.Software, u"\u8774\u8776 h\xfadi\xe9 'butterfly'")
        msg.add_attr(stun.AlternateServer, stun.Address.FAMILY_IPv4, 8008, '192.168.2.128')
        msg.add_attr(stun.Fingerprint)

        msg_data = (
            '000100bc2112a4426669786564747261'
            '6e736964666600046461746100010008'
            '00010539c0a802ff000600076a6f686e'
            '646f6500000800144ad36bd8d0c242f6'
            'a2b98ccbcfe0f21432261fb400090010'
            '00000500536572766572204572726f72'
            '000a00061337b00bbeef000000140009'
            '70657869702e636f6d00000000150010'
            '36303332376331373134356137373838'
            '002000080001242be1baa6bd8022001a'
            'e89db4e89db62068c3ba6469c3a92027'
            '627574746572666c7927000080230008'
            '00011f48c0a8028080280004e43217b7')

        self.assertEqual(str(msg), msg_data.decode('hex'))


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
