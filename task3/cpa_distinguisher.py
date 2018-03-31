from filecoder import encode, encode_challenge
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def iv_generator():
    iv = get_random_bytes(16)
    iv_hex = iv.hex()
    i = int(iv_hex, 16)
    while True:
        yield i.to_bytes(16, 'big')
        i += 1


class Oracle:
    mode = AES.MODE_CBC

    def __init__(self, flawed=False):
        self.key = get_random_bytes(32)
        self._iv = None
        self.b = None
        self.flawed = flawed
        if flawed:
            self._iv_generator = iv_generator()

    def next_iv(self):
        if not self.flawed:
            self._iv = get_random_bytes(16)
        else:
            self._iv = next(self._iv_generator)
        return self._iv

    def encode(self, plain_bytes):
        if type(plain_bytes) in (list, tuple):
            payload = []
            for plain in plain_bytes:
                cipher, iv = encode(self.mode, self.key, plain, iv=self.next_iv())
                payload.append((cipher, iv))
            return payload
        else:
            return encode(self.mode, self.key, plain_bytes, iv=self.next_iv())

    def encode_challenge(self, plain_bytes):
        (ciphertext, iv), b = encode_challenge(self.mode, self.key, plain_bytes, iv=self.next_iv())
        self.b = b
        return ciphertext, iv

    def __str__(self):
        return "<Oracle key:{} iv:{} b:{}>".format(self.key, self._iv, self.b)


def xor_bytes(b1, b2):
    from sys import byteorder
    b2 = b2[:len(b1)]
    int_var = int.from_bytes(b1, byteorder)
    int_key = int.from_bytes(b2, byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(b1), byteorder)


def main(flawed):
    won = 0
    lost = 0
    try:
        while True:
            oracle = Oracle(flawed=flawed)

            m0 = get_random_bytes(AES.block_size)
            m1 = get_random_bytes(AES.block_size)
            m = m0 + m1

            c1, iv1 = oracle.encode(m)

            iv1_hex = iv1.hex()
            iv1_int = int(iv1_hex, 16)
            iv1_plus1 = (iv1_int+1).to_bytes(16, 'big')

            w0 = xor_bytes(xor_bytes(m0, iv1), iv1_plus1)
            w1 = get_random_bytes(AES.block_size)

            w = w0 + w1

            v0 = get_random_bytes(AES.block_size)
            while v0 == w0:
                v0 = get_random_bytes(AES.block_size)
            v = v0 + w1

            c2, iv2 = oracle.encode_challenge([w, v])

            if c2[:AES.block_size] == c1[:AES.block_size]:
                b = 0
            else:
                b = 1
            try:
                assert oracle.b == b, "b != b'"
                won += 1
            except AssertionError:
                lost += 1
    except KeyboardInterrupt:
        print("\nwon: {}\tlost: {}".format(won, lost))
        if won+lost > 0:
            print("{:.2%} win ratio against {} Oracle".format(won/(won+lost), 'flawed' if flawed else 'proper'))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser("CPA-distinguisher fighting with flawed or proper AES CBC mode Oracle. "
                                     "If Oracle is flawed, that means the iv is incremented by 1 each time it encodes."
                                     "Proper Oracle always picks random iv."
                                     "Program runs until it is interrupted by the user, printing win ratio.")
    parser.add_argument('-f', action='store_true', dest='flawed', help='use flawed Oracle')
    args = parser.parse_args()

    main(args.flawed)
