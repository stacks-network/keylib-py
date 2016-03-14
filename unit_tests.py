import json
import unittest
import traceback
from test import test_support

from keylib import (
    b58check_encode, b58check_decode, b58check_unpack,
    ECPrivateKey, ECPublicKey
)

_reference_info = {
    'passphrase': 'correct horse battery staple',
    'bin_private_key': '\xc4\xbb\xcb\x1f\xbe\xc9\x9de\xbfY\xd8\\\x8c\xb6.\xe2\xdb\x96?\x0f\xe1\x06\xf4\x83\xd9\xaf\xa7;\xd4\xe3\x9a\x8a',
    'hex_private_key': 'c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a',
    'hex_public_key': '0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
    'hex_hash160': 'c4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827',
    'wif_private_key': '5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS',
    'address': '1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T',
    'wif_version_byte': 128,
    'pem_private_key': '-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIMS7yx++yZ1lv1nYXIy2LuLblj8P4Qb0g9mvpzvU45qKoAcGBSuBBAAK\noUQDQgAEeNQwJ0+MXsEyEzgVHp8n9MZ2oAi9+GONB8C2vpqzXHGhUYBjJDrNTf6W\ntm4/LsgBPI4HLNCbODShn4H2Wcw0VQ==\n-----END EC PRIVATE KEY-----\n',
    'pem_public_key': '-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEeNQwJ0+MXsEyEzgVHp8n9MZ2oAi9+GON\nB8C2vpqzXHGhUYBjJDrNTf6Wtm4/LsgBPI4HLNCbODShn4H2Wcw0VQ==\n-----END PUBLIC KEY-----\n',
    'der_private_key': '30740201010420c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8aa00706052b8104000aa1440342000478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
    'der_public_key': '3056301006072a8648ce3d020106052b8104000a0342000478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455'
}


class ECPrivateKeyTest(unittest.TestCase):
    reference = _reference_info

    def setUp(self):
        self.private_key = ECPrivateKey(self.reference['hex_private_key'], compressed=False)

    def tearDown(self):
        pass

    def test_random_private_key(self):
        private_key = ECPrivateKey()
        self.assertTrue(isinstance(private_key, ECPrivateKey))

    def test_private_key_from_wif(self):
        self.private_key_from_wif = ECPrivateKey(
            self.reference['wif_private_key'], compressed=False)
        self.assertEqual(
            self.private_key.to_hex(), self.private_key_from_wif.to_hex())

    def test_hex_private_key(self):
        self.assertEqual(
            self.private_key.to_hex(), self.reference['hex_private_key'])

    def test_wif_private_key(self):
        self.assertEqual(
            self.private_key.to_wif(), self.reference['wif_private_key'])

    def test_pem_private_key(self):
        self.assertEqual(
            self.private_key.to_pem(), self.reference['pem_private_key'])

    def test_der_private_key(self):
        self.assertEqual(
            self.private_key.to_der(), self.reference['der_private_key'])


class ECPublicKeyCreationTest(unittest.TestCase):
    def setUp(self):
        self.address_compressed = '14Q8uVAX29RUMvqPGXL5sg6NiwwMRFCm8C'
        self.address_uncompressed = '1AuZor1RVzG22wqbH2sG2j5WRDZsbw1tip'

    def tearDown(self):
        pass

    def test_create_pubkey_from_hex_uncompressed_format(self):
        public_key_string = '04068fd9d47283fb310e6dfb66b141dd78fbabc76d073d48cddc770ffb2bd262d7b2832f87f683100b89c2e95314deeeacbc6409af1e36c3ae3fd8c5f2f243cfec'
        self.assertEqual(self.address_uncompressed, ECPublicKey(
            public_key_string).address())

    def test_create_pubkey_from_bin_uncompressed_format(self):
        public_key_string = '\x04\x06\x8f\xd9\xd4r\x83\xfb1\x0em\xfbf\xb1A\xddx\xfb\xab\xc7m\x07=H\xcd\xdcw\x0f\xfb+\xd2b\xd7\xb2\x83/\x87\xf6\x83\x10\x0b\x89\xc2\xe9S\x14\xde\xee\xac\xbcd\t\xaf\x1e6\xc3\xae?\xd8\xc5\xf2\xf2C\xcf\xec'
        self.assertEqual(self.address_uncompressed, ECPublicKey(
            public_key_string).address())

    def test_create_pubkey_from_hex_ecdsa_format(self):
        public_key_string = '068fd9d47283fb310e6dfb66b141dd78fbabc76d073d48cddc770ffb2bd262d7b2832f87f683100b89c2e95314deeeacbc6409af1e36c3ae3fd8c5f2f243cfec'
        self.assertEqual(self.address_uncompressed, ECPublicKey(
            public_key_string).address())

    def test_create_pubkey_from_bin_ecdsa_format(self):
        public_key_string = '\x06\x8f\xd9\xd4r\x83\xfb1\x0em\xfbf\xb1A\xddx\xfb\xab\xc7m\x07=H\xcd\xdcw\x0f\xfb+\xd2b\xd7\xb2\x83/\x87\xf6\x83\x10\x0b\x89\xc2\xe9S\x14\xde\xee\xac\xbcd\t\xaf\x1e6\xc3\xae?\xd8\xc5\xf2\xf2C\xcf\xec'
        self.assertEqual(self.address_uncompressed, ECPublicKey(
            public_key_string).address())

    def test_create_pubkey_from_hex_compressed_format(self):
        public_key_string = '02068fd9d47283fb310e6dfb66b141dd78fbabc76d073d48cddc770ffb2bd262d7'
        self.assertEqual(self.address_compressed, ECPublicKey(
            public_key_string).address())

    def test_create_pubkey_from_bin_compressed_format(self):
        public_key_string = '\x02\x06\x8f\xd9\xd4r\x83\xfb1\x0em\xfbf\xb1A\xddx\xfb\xab\xc7m\x07=H\xcd\xdcw\x0f\xfb+\xd2b\xd7'
        self.assertEqual(self.address_compressed, ECPublicKey(
            public_key_string).address())


class BitcoinUncompressedPublicKeyTest(unittest.TestCase):
    reference = _reference_info

    def setUp(self):
        self.public_key = ECPublicKey(self.reference['hex_public_key'])

    def tearDown(self):
        pass

    def test_address(self):
        self.assertEqual(self.public_key.address(), self.reference['address'])

    def test_hex_hash160(self):
        self.assertEqual(
            self.public_key.hash160(), self.reference['hex_hash160'])

    def test_hex_public_key(self):
        self.assertEqual(
            self.public_key.to_hex(), self.reference['hex_public_key'])

    def test_pem_public_key(self):
        self.assertEqual(
            self.public_key.to_pem(), self.reference['pem_public_key'])

    def test_der_public_key(self):
        self.assertEqual(
            self.public_key.to_der(), self.reference['der_public_key'])


class BitcoinCompressedPublicKeyTest(unittest.TestCase):
    def setUp(self):
        self.reference = {
            'hex_public_key': '02068fd9d47283fb310e6dfb66b141dd78fbabc76d073d48cddc770ffb2bd262d7',
            'bin_public_key': '\x02\x06\x8f\xd9\xd4r\x83\xfb1\x0em\xfbf\xb1A\xddx\xfb\xab\xc7m\x07=H\xcd\xdcw\x0f\xfb+\xd2b\xd7',
            'hex_hash160': '25488b0d3bb770d6e0ef07e1f19d33ab59931dee',
            'bin_hash160': '%H\x8b\r;\xb7p\xd6\xe0\xef\x07\xe1\xf1\x9d3\xabY\x93\x1d\xee',
            'address': '14Q8uVAX29RUMvqPGXL5sg6NiwwMRFCm8C',
        }
        self.public_key = ECPublicKey(self.reference['hex_public_key'])

    def tearDown(self):
        pass

    def test_address(self):
        self.assertEqual(self.public_key.address(), self.reference['address'])

    def test_bin_hash160(self):
        self.assertEqual(
            self.public_key.bin_hash160(), self.reference['bin_hash160'])

    def test_hex_hash160(self):
        self.assertEqual(
            self.public_key.hash160(), self.reference['hex_hash160'])

    def test_bin_public_key(self):
        self.assertEqual(
            self.public_key.to_bin(), self.reference['bin_public_key'])

    def test_hex_public_key(self):
        self.assertEqual(
            self.public_key.to_hex(), self.reference['hex_public_key'])


class ECPrivateKeyToPublicKeyTest(unittest.TestCase):
    reference = _reference_info

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_private_key_to_public_key_conversion(self):
        priv = ECPrivateKey(self.reference['hex_private_key'], compressed=False)
        pub = priv.public_key()
        self.assertEqual(pub.to_hex(), self.reference['hex_public_key'])
        self.assertEqual(pub.address(), self.reference['address'])


class BitcoinB58CheckTest(unittest.TestCase):
    reference = _reference_info

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_b58check_encode_then_decode(self):
        bin_private_key = self.reference['hex_private_key'].decode('hex')
        wif_private_key = b58check_encode(
            bin_private_key, version_byte=self.reference['wif_version_byte'])
        self.assertEqual(self.reference['wif_private_key'], wif_private_key)
        bin_private_key_verification = b58check_decode(wif_private_key)
        self.assertEqual(bin_private_key_verification, bin_private_key)

    def test_b58check_unpack_then_encode(self):
        version_byte, bin_private_key, checksum = b58check_unpack(
            self.reference['wif_private_key'])
        self.assertTrue(
            ord(version_byte) == self.reference['wif_version_byte'])
        wif_private_key = b58check_encode(
            bin_private_key, version_byte=ord(version_byte))
        self.assertEqual(self.reference['wif_private_key'], wif_private_key)

def test_main():
    test_support.run_unittest(
        ECPrivateKeyTest,
        ECPublicKeyCreationTest,
        BitcoinUncompressedPublicKeyTest,
        BitcoinCompressedPublicKeyTest,
        ECPrivateKeyToPublicKeyTest,
        BitcoinB58CheckTest
    )

if __name__ == '__main__':
    test_main()