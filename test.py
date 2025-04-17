import unittest
import rsa


class TestRsa(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key, self.public_key = rsa.generate_key_pair()

    def test_encoding(self):
        self.assertEqual(
            505,
            rsa.decode(
                rsa.encode(505, self.public_key),
                self.private_key,
            ),
        )
