import unittest
import rsa


class TestPrime(unittest.TestCase):
    def setUp(self) -> None:
        self.primality_dict = {
            1013: True,
            1021: True,
            1033: True,
            1049: True,
            1061: True,
            1069: True,
            1103: True,
            1117: True,
            1151: True,
            1181: True,
            1193: True,
            1231: True,
            1277: True,
            1291: True,
            1301: True,
            1000: False,
            1020: False,
            1040: False,
            1060: False,
            1080: False,
            1100: False,
            1122: False,
            1140: False,
            1166: False,
            1188: False,
            1200: False,
            1222: False,
            1244: False,
            1260: False,
            1288: False,
        }

    def test_primality(self) -> None:
        for k, v in self.primality_dict.items():
            self.assertEqual(rsa.is_prime(k, 40), v)


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
