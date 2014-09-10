import unittest
from aes import AES, encrypt, decrypt

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


class TestFunctions(unittest.TestCase):
    """
    Tests the module functions `encrypt` and `decrypt`, as well as basic
    security features like randomization and integrity.
    """
    def setUp(self):
        self.key = b'master key'
        self.message = b'secret message'
        # Lower workload then default to speed up tests.
        self.encrypt = lambda key, ciphertext: encrypt(key, ciphertext, 10000)
        self.decrypt = lambda key, ciphertext: decrypt(key, ciphertext, 10000)

    def test_success(self):
        ciphertext = self.encrypt(self.key, self.message)
        self.assertEqual(self.decrypt(self.key, ciphertext), self.message)

    def test_long_message(self):
        ciphertext = self.encrypt(self.key, self.message * 100)
        self.assertEqual(self.decrypt(self.key, ciphertext), self.message * 100)

    def test_sanity(self):
        ciphertext = self.encrypt(self.key, self.message)
        self.assertNotIn(self.key, ciphertext)
        self.assertNotIn(self.message, ciphertext)

    def test_randomization(self):
        ciphertext1 = self.encrypt(self.key, self.message)
        ciphertext2 = self.encrypt(self.key, self.message)
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_integrity(self):
        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.key, self.message)
            ciphertext += b'a'
            self.decrypt(self.key, ciphertext)

        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.key, self.message)
            ciphertext = ciphertext[:-1]
            self.decrypt(self.key, ciphertext)

        with self.assertRaises(AssertionError):
            ciphertext = self.encrypt(self.key, self.message)
            ciphertext = ciphertext[:-1] + b'a'
            self.decrypt(self.key, ciphertext)



if __name__ == '__main__':
    unittest.main()
