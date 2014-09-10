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
        self.message = b'my message'

    def test_single_block(self):
        ciphertext = self.aes.encrypt_cbc(self.message, self.iv)
        self.assertEqual(len(ciphertext), 16)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), self.message)

    def test_wrong_iv(self):
        with self.assertRaises(AssertionError):
            self.aes.encrypt_cbc(self.message, b'short iv')

        with self.assertRaises(AssertionError):
            self.aes.encrypt_cbc(self.message, b'long iv' * 16)

    def test_different_iv(self):
        iv2 = b'\02' * 16

        ciphertext1 = self.aes.encrypt_cbc(self.message, self.iv)
        ciphertext2 = self.aes.encrypt_cbc(self.message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes.decrypt_cbc(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt_cbc(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, self.message)

    def test_whole_block_padding(self):
        block_message = b'M' * 16
        ciphertext = self.aes.encrypt_cbc(block_message, self.iv)
        self.assertEqual(len(ciphertext), 32)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), block_message)

    def test_long_message(self):
        long_message = b'M' * 100
        ciphertext = self.aes.encrypt_cbc(long_message, self.iv)
        self.assertEqual(self.aes.decrypt_cbc(ciphertext, self.iv), long_message)


if __name__ == '__main__':
    unittest.main()
