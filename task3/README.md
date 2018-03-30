AES file decoder/encoder
========================

## Description

File encrypting/decrypting with cryptographic keys loaded from Java KeyStore in
JCEKS keystore `.jck` file. Program supports AES standard with OFB, CBC, CTR and
GCM modes. Nonce/iv/counter is generated randomly and saved in front of
cryptogram. Program uses PyCryptodome library for all encrypting and decrypting 
operations with AES. For Java KeyStore parsing and decryption PyJKS is used.

On run, passwords for keystore and selected key will have to be provided.

Encrypted files are saved under input file name with `.aes` suffix.

Challenge mode for encryption allows providing 2 files, from which one, selected 
uniformly at random, will be encrypted and saved in `challenge.aes`.

## Usage

```
usage: filecoder.py [-h] [-s KEYSTORE_PATH] [-k KEY_ID] [-c]
                    {encode,decode} {cbc,ctr,ofb,gcm} files [files ...]

positional arguments:
  {encode,decode}    mode of operation
  {cbc,ctr,ofb,gcm}  encryption mode
  files              files to encode/decode

optional arguments:
  -h, --help         show this help message and exit
  -s KEYSTORE_PATH   keystore path
  -k KEY_ID          key identifier
  -c                 challenge mode: on input m0, m1 your program picks
                     independently, uniformly at random a bit `b` and returns
                     a ciphertext cb of a message mb
```
