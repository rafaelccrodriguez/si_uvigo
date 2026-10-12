import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa

from onion_protocol import Delivered, Forward, build_onion, decode_or_relay


class OnionProtocolTests(unittest.TestCase):
    def setUp(self):
        self.route = ["demo", "rly1", "rly2", "dest"]
        self.private = {
            user_id: rsa.generate_private_key(public_exponent=65537, key_size=2048)
            for user_id in self.route
        }
        self.public = {user_id: key.public_key() for user_id, key in self.private.items()}

    def test_message_crosses_relays_and_is_delivered(self):
        first_hop, packet = build_onion(self.route, self.public, "demo", "ola, mundo")
        self.assertEqual(first_hop, "rly1")

        first = decode_or_relay(self.private["rly1"], packet)
        self.assertIsInstance(first, Forward)
        self.assertEqual(first.next_hop, "rly2")

        second = decode_or_relay(self.private["rly2"], first.packet)
        self.assertIsInstance(second, Forward)
        self.assertEqual(second.next_hop, "dest")

        delivered = decode_or_relay(self.private["dest"], second.packet)
        self.assertEqual(delivered, Delivered(sender="demo", message="ola, mundo"))

    def test_packet_tampering_is_detected_by_aes_gcm(self):
        _, packet = build_onion(self.route, self.public, "demo", "nao altere")
        tampered = bytearray(packet)
        tampered[-1] ^= 1
        with self.assertRaises(InvalidTag):
            decode_or_relay(self.private["rly1"], bytes(tampered))


if __name__ == "__main__":
    unittest.main(verbosity=2)
