import string
import time

alphabet = string.ascii_letters + ' ,.'
key_codes = ["{0:b}".format(i).zfill(8) for i in range(2 ** 8)]
ascii_table = {format(ord(x), '08b'): x for x in alphabet}
ascii_codes = [format(ord(x), '08b') for x in alphabet]


def isaccepted(x):
    return x in ascii_table


def isspace(x):
    return x == format(ord(' '), '08b')


def islowercase(x):
    return x in [format(ord(x), '08b') for x in string.ascii_lowercase]


def xor(a, b):
    return '0' if (a == b) else '1'


def xor_bytes(b1, b2):
    return ''.join([xor(a, b) for (a, b) in zip(b1, b2)])


def get_data(filename):
    with open(filename, 'r') as f:
        size = int(f.readline())
        return [f.readline().rstrip('\n') for _ in range(size)]


def find_key(ciphertexts, wanted_index=-1):
    max_len = len(ciphertexts[wanted_index])
    key = ['*' for _ in range(max_len // 8)]

    for index, i in enumerate(range(0, max_len-8, 8)):
        key_guesses = {code: 0 for code in key_codes}
        for c in key_codes:
            for cipher in ciphertexts:
                char = cipher[i:i + 8]
                if not char:
                    continue
                xored = xor_bytes(c, char)
                if isaccepted(xored):
                    key_guesses[c] += 1
                    if isspace(xored):
                        key_guesses[c] += 1
        sorted_guesses = sorted(key_guesses, key=lambda x: key_guesses[x], reverse=True)
        for guess in sorted_guesses:
            char = ciphertexts[wanted_index][i:i + 8]
            xored = xor_bytes(guess, char)
            if isaccepted(xored):
                key[index] = guess
                break

    return key


def decrypt(ciphertext, key):
    return ''.join([str(c) for c in decryption_generator(ciphertext, key)])


def decryption_generator(ciphertext, key):
    ciphertext_bytes = [ciphertext[i:i + 8] for i in range(0, len(ciphertext) - 8, 8)]
    if len(ciphertext_bytes) > len(key):
        raise IndexError("Key is too short")
    for (c, k) in zip(ciphertext_bytes, key):
        try:
            if k == '*':
                raise ValueError
            xored = xor_bytes(c, k)
            yield ascii_table[xored]
        except (KeyError, ValueError):
            yield '#'


if __name__ == "__main__":
    start = time.process_time()
    data = get_data('ciphertexts.txt')

    key = find_key(data, wanted_index=-1)
    print(decrypt(data[-1], key))

    end = time.process_time()
    print(f"----------------- {end - start} seconds")
