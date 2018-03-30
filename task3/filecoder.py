import sys
import jks

from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Util import Padding
from os import path

ENCODE = 'encode'
DECODE = 'decode'

SUPPORTED_MODES = {
    'cbc': AES.MODE_CBC,
    'ctr': AES.MODE_CTR,
    'ofb': AES.MODE_OFB,
    'gcm': AES.MODE_GCM,
}

IV_MODES = [AES.MODE_CBC, AES.MODE_OFB, AES.MODE_CFB]
NONCE_MODES = [AES.MODE_CCM, AES.MODE_EAX, AES.MODE_GCM,
               AES.MODE_SIV, AES.MODE_OCB, AES.MODE_CTR]

SEPARATOR = b'==='


def encode(mode, key, files, challenge=False):
    if challenge:
        b = random.choice([0, 1])
        files = [files[b]]
    total_files = len(files)
    for i, file_path in enumerate(files, start=1):
        print("{}/{}: Encoding ...".format(i, total_files))
        cipher, nonce = aes_encoder(mode, key)
        if not challenge:
            output_path = '.'.join([file_path, 'aes'])
        else:
            output_path = '/'.join([path.abspath(file_path).rsplit('/', maxsplit=1)[0], 'challenge.aes'])
        with open(file_path, mode='rb') as file:
            plain = file.read()
            if mode == AES.MODE_CBC:
                plain = Padding.pad(plain, AES.block_size, style='iso7816')
            encrypted = cipher.encrypt(plain)
        with open(output_path, mode='wb') as file:
            output = SEPARATOR.join([nonce, encrypted])
            file.write(output)
        print("Successfully encoded into {}".format(output_path))


def decode(mode, key, files):
    total_files = len(files)
    for i, file_path in enumerate(files, start=1):
        print("{}/{}: Decoding {} ...".format(i, total_files, file_path))
        with open(file_path, mode='rb') as file:
            file_bytes = file.read()
            nonce, ciphertext = file_bytes.split(SEPARATOR, maxsplit=1)
            try:
                cipher = aes_decoder(mode, key, nonce)
                decrypted = cipher.decrypt(ciphertext)
            except ValueError:
                print("There was problem with decryption, make sure proper key and mode of operation is provided, "
                      "program will now close")
                return
        output_path = file_path.replace('.aes', '')
        with open(output_path, mode='wb') as file:
            try:
                file.write(Padding.unpad(decrypted, AES.block_size, style='iso7816'))
            except ValueError:
                file.write(decrypted)
        print("Successfully decoded into {}".format(output_path))


def aes_encoder(mode, key):
    cipher = AES.new(key, mode)
    if mode in IV_MODES:
        return cipher, cipher.iv
    else:
        return cipher, cipher.nonce


def aes_decoder(mode, key, nonce):
    if mode not in SUPPORTED_MODES.values():
        raise ValueError("Used mode is not supported")
    if mode in IV_MODES:
        return AES.new(key, mode, iv=nonce)
    else:
        return AES.new(key, mode, nonce=nonce)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="File coding/decoding with cryptographic keys loaded from "
                                                 "Java KeyStore in JCEKS keystore format .jkc. Program supports "
                                                 "AES standard with CBC, CTR and GCM modes. Nonce/iv/counter "
                                                 "is generated randomly and saved in front of cryptogram.\n"
                                                 "Program uses PyCryptodome library for all encrypting and decrypting "
                                                 "operations with AES.\n"
                                                 "For Java KeyStore parsing and decryption PyJKS is used.")
    parser.add_argument('operation', type=str, help='mode of operation', choices=[ENCODE, DECODE], default=ENCODE)
    parser.add_argument('mode', type=str, help='encryption mode', choices=SUPPORTED_MODES.keys(), default='cbc')
    parser.add_argument('files', type=str, nargs='+', help='files to encode/decode')
    parser.add_argument('-s', type=str, dest='keystore_path', help='keystore path', default='keystore.jks')
    parser.add_argument('-k', type=str, dest='key_id', help='key identifier', default='myaeskey')
    parser.add_argument('-c', action='store_true', dest='challenge', help='challenge mode: on input m0, m1 your '
                                                                          'program picks independently, uniformly '
                                                                          'at random a bit `b` and returns '
                                                                          'a ciphertext cb of a message mb')

    args = parser.parse_args()

    operation = args.operation
    mode = SUPPORTED_MODES[args.mode]
    files = args.files
    if operation == DECODE:
        for f in files:
            if not f.endswith('.aes'):
                print("Only *.aes files are supported for decryption, program will now close")
                return
    keystore_path = args.keystore_path
    key_id = args.key_id
    challenge = args.challenge
    if challenge:
        if mode == DECODE:
            print("Challenge mode available only in encryption")
            return
        if len(files) != 2:
            print("For challenge mode exactly 2 input files are required")
            return

    keystore = None
    while keystore is None:
        try:
            keystore_password = getpass("Enter passphrase for keystore under {}: ".format(keystore_path))
            keystore = jks.KeyStore.load(keystore_path, keystore_password, False)
        except jks.KeystoreSignatureException:
            print("Wrong passphrase, keystore cannot be opened, try again")
        except (jks.BadKeystoreFormatException, jks.UnsupportedKeystoreVersionException, jks.DuplicateAliasException):
            print("There was problem with the keystore, program will now close")
            return

    key = keystore.entries[key_id]
    while not key.is_decrypted():
        key_password = getpass("Enter passphrase for key <{}>: ".format(key_id))
        try:
            key.decrypt(key_password)
        except jks.DecryptionFailureException or ValueError:
            print("Wrong passphrase, key cannot be decrypted, try again")
        except jks.UnexpectedAlgorithmException:
            print("There was problem with the key, program will now close")
            return

    if operation == ENCODE:
        encode(mode, key.key, files, challenge=challenge)
    elif operation == DECODE:
        decode(mode, key.key, files)
    else:
        print("Operation is invalid, accepted arguments are {}".format([ENCODE, DECODE]))
        return


if __name__ == "__main__":
    main()
