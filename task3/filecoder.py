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


def encode_files(mode, key, files, challenge=False, iv=None, nonce=None):
    try:
        if challenge:
            if len(files) != 2:
                print("For challenge mode exactly 2 input files are required")
                return
            print("Encoding challenge ...")
            output_path = '/'.join([path.abspath(files[0]).rsplit('/', maxsplit=1)[0], 'challenge.aes'])
            with open(files[0], mode='rb') as file:
                plain_1 = file.read()
            with open(files[0], mode='rb') as file:
                plain_2 = file.read()
            (ciphertext, nonce), b = encode_challenge(mode, key, (plain_1, plain_2), iv=iv, nonce=nonce)
            with open(output_path, mode='wb') as file:
                output = SEPARATOR.join([nonce, ciphertext])
                file.write(output)
        else:
            total_files = len(files)
            for i, file_path in enumerate(files, start=1):
                print("{}/{}: Encoding ...".format(i, total_files))
                output_path = '.'.join([file_path, 'aes'])
                with open(file_path, mode='rb') as file:
                    plain = file.read()
                ciphertext, nonce = encode(mode, key, plain, iv=iv, nonce=nonce)
                with open(output_path, mode='wb') as file:
                    output = SEPARATOR.join([nonce, ciphertext])
                    file.write(output)
                print("Successfully encoded into {}".format(output_path))
    except (ValueError, TypeError) as e:
        print("There was problem with encryption: {}, make sure proper key and mode of operation is provided, "
              "program will now close".format(e))
        return
    except FileNotFoundError as e:
        print("File '{}' not found, program will now close".format(e.filename))
        return


def encode_challenge(mode, key, plain_bytes_tuple, iv=None, nonce=None):
    if type(plain_bytes_tuple) not in (list, tuple):
        raise TypeError("Challenge requires list or tuple of two inputs")
    if len(plain_bytes_tuple) != 2:
        raise ValueError("Challenge requires exactly two inputs")
    b = random.choice([0, 1])
    plain_bytes = plain_bytes_tuple[b]
    return encode(mode, key, plain_bytes, iv=iv, nonce=nonce), b


def encode(mode, key, plain_bytes, iv=None, nonce=None):
    if mode == AES.MODE_CBC:
        plain_bytes = Padding.pad(plain_bytes, AES.block_size, style='iso7816')
    cipher, nonce = aes_encoder(mode, key, iv=iv, nonce=nonce)
    ciphertext = cipher.encrypt(plain_bytes)
    return ciphertext, nonce


def decode_files(mode, key, files):
    try:
        total_files = len(files)
        for i, file_path in enumerate(files, start=1):
            print("{}/{}: Decoding {} ...".format(i, total_files, file_path))
            with open(file_path, mode='rb') as file:
                file_bytes = file.read()
                nonce, ciphertext = file_bytes.split(SEPARATOR, maxsplit=1)
                if mode in IV_MODES:
                    iv = nonce
                    nonce = None
                else:
                    iv = None
                plain = decode(mode, key, ciphertext, iv=iv, nonce=nonce)
            output_path = file_path.replace('.aes', '')
            with open(output_path, mode='wb') as file:
                try:
                    file.write(Padding.unpad(plain, AES.block_size, style='iso7816'))
                except ValueError:
                    file.write(plain)
            print("Successfully decoded into {}".format(output_path))
    except ValueError as e:
        print("There was problem with decryption: {}, make sure proper key and mode of operation is provided, "
              "program will now close".format(e))
        return
    except FileNotFoundError as e:
        print("File '{}' not found, program will now close".format(e.filename))
        return


def decode(mode, key, ciphertext_bytes, iv=None, nonce=None):
    cipher = aes_decoder(mode, key, iv=iv, nonce=nonce)
    plain = cipher.decrypt(ciphertext_bytes)
    return plain


def aes_encoder(mode, key, iv=None, nonce=None):
    if mode not in SUPPORTED_MODES.values():
        raise ValueError("Used mode is not supported")
    if mode in IV_MODES:
        if iv:
            cipher = AES.new(key, mode, iv=iv)
        else:
            cipher = AES.new(key, mode)
        return cipher, cipher.iv
    else:
        if nonce:
            cipher = AES.new(key, mode, nonce=nonce)
        else:
            cipher = AES.new(key, mode)
        return cipher, cipher.nonce


def aes_decoder(mode, key, iv=None, nonce=None):
    if mode not in SUPPORTED_MODES.values():
        raise ValueError("Used mode is not supported")
    if mode in IV_MODES:
        if not iv:
            raise ValueError("IV has to be provided")
        return AES.new(key, mode, iv=iv)
    else:
        if not nonce:
            raise ValueError("Nonce has to be provided")
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
    parser.add_argument('-i', type=str, dest='iv', help='predefined encoding iv', default=None)
    parser.add_argument('-n', type=str, dest='nonce', help='predefined encoding nonce', default=None)
    parser.add_argument('-c', action='store_true', dest='challenge', help='challenge mode: on input m0, m1 your '
                                                                          'program picks independently, uniformly '
                                                                          'at random a bit `b` and returns '
                                                                          'a ciphertext cb of a message mb')

    args = parser.parse_args()

    operation = args.operation
    mode = SUPPORTED_MODES[args.mode]
    files = args.files
    iv = args.iv
    nonce = args.nonce
    if operation == DECODE:
        if iv or nonce:
            print("Only encryption can use predefined iv/nonce, program will now close")
            return
        for f in files:
            if not f.endswith('.aes'):
                print("Only *.aes files are supported for decryption, program will now close")
                return
    if iv and nonce:
        print("Either 'iv' or 'nonce' can be provided, not both, program will now close")
        return
    if iv and mode in NONCE_MODES:
        print("Chosen encoding mode uses 'nonce' but 'iv' was provided, program will now close")
        return
    if nonce and mode in IV_MODES:
        print("Chosen encoding mode uses 'iv' but 'nonce' was provided, program will now close")
        return
    keystore_path = args.keystore_path
    key_id = args.key_id
    challenge = args.challenge
    if challenge:
        if mode == DECODE:
            print("Challenge mode available only in encryption")
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
        encode_files(mode, key.key, files, challenge=challenge, iv=iv, nonce=nonce)
    elif operation == DECODE:
        decode_files(mode, key.key, files)
    else:
        print("Operation is invalid, accepted arguments are {}".format([ENCODE, DECODE]))
        return


if __name__ == "__main__":
    main()
