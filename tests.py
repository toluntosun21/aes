import unittest
from aes import AES

class TestBlock(unittest.TestCase):
    """
    Tests raw AES-128 block operations.
    """
    def setUp(self):
        self.aes = AES(b'\00' * 16)

    def test_success(self):
        message = b'\01' * 16
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)

        message = b'a secret message'
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)

    def test_bad_key(self):
        with self.assertRaises(AssertionError):
            AES(b'short key')

        with self.assertRaises(AssertionError):
            AES(b'long key' * 10)

class TestCbc(unittest.TestCase):
    """
    Tests AES-128 in CBC mode.
    """
    def setUp(self):
        self.aes = AES(b'\00' * 16)
        self.iv = b'\01' * 16

    def test_single_block(self):
        message = b'my message'
        ciphertext = self.aes.encrypt_cbc(message, self.iv)
        self.assertEqual(len(ciphertext), 16)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), message)



if __name__ == '__main__':
    unittest.main()
