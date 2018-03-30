import shutil
import tempfile
import unittest
import os
from os import path

from Crypto.Random import get_random_bytes
import filecoder


class TestEncryptionModes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = get_random_bytes(32)
        cls.key2 = cls.key[8:] + cls.key[:8]

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.secret_message = get_random_bytes(1024*1024*10)  # 10MB files
        self.input_file = path.join(self.test_dir, 'test')
        self.output_file = path.join(self.test_dir, 'test.aes')
        with open(self.input_file, 'wb') as f:
            f.write(self.secret_message)

    def remove_input(self):
        os.remove(self.input_file)
        self.assertRaises(FileNotFoundError, open, self.input_file, 'r')

    def check_plaintext(self):
        with open(self.input_file, 'rb') as f:
            self.assertEqual(f.read(), self.secret_message)

    def check_ciphertext(self):
        with open(self.output_file, 'rb') as f:
            content = f.read()
            self.assertIn(filecoder.SEPARATOR, content)
            nonce, ciphertext = content.split(filecoder.SEPARATOR, maxsplit=1)
            self.assertGreater(len(nonce), 0)
            self.assertGreater(len(ciphertext), 0)

    def run_test(self, mode, encryption_key, decryption_key):
        self.check_plaintext()
        filecoder.encode(mode, encryption_key, [self.input_file])
        self.check_ciphertext()
        self.remove_input()
        filecoder.decode(mode, decryption_key, [self.output_file])
        self.check_plaintext()

    def test_cbc(self):
        mode = filecoder.SUPPORTED_MODES['cbc']
        self.run_test(mode, self.key, self.key)

    def test_ctr(self):
        mode = filecoder.SUPPORTED_MODES['ctr']
        self.run_test(mode, self.key, self.key)

    def test_ofb(self):
        mode = filecoder.SUPPORTED_MODES['ofb']
        self.run_test(mode, self.key, self.key)

    def test_gcm(self):
        mode = filecoder.SUPPORTED_MODES['gcm']
        self.run_test(mode, self.key, self.key)

    def test_cbc_wrong_key(self):
        mode = filecoder.SUPPORTED_MODES['cbc']
        self.assertRaises(AssertionError, self.run_test, mode, self.key, self.key2)

    def test_ctr_wrong_key(self):
        mode = filecoder.SUPPORTED_MODES['ctr']
        self.assertRaises(AssertionError, self.run_test, mode, self.key, self.key2)

    def test_ofb_wrong_key(self):
        mode = filecoder.SUPPORTED_MODES['ofb']
        self.assertRaises(AssertionError, self.run_test, mode, self.key, self.key2)

    def test_gcm_wrong_key(self):
        mode = filecoder.SUPPORTED_MODES['gcm']
        self.assertRaises(AssertionError, self.run_test, mode, self.key, self.key2)

    def test_wrong_mode(self):
        self.assertRaises(ValueError, filecoder.encode, None, self.key, [self.input_file])

    def tearDown(self):
        shutil.rmtree(self.test_dir)


if __name__ == '__main__':
    unittest.main()
