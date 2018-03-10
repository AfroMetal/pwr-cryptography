import random
from math import gcd
from functools import reduce


def glibc_prng(s):
    # glibc random() 
    # source: https://github.com/qbx2/python_glibc_random/blob/master/glibc_prng.py
    # reference: https://www.mscs.dal.ca/~selinger/random/

    int32 = lambda x: x & 0xffffffff - 0x100000000 if x & 0xffffffff > 0x7fffffff else x & 0xffffffff
    int64 = lambda \
        x: x & 0xffffffffffffffff - 0x10000000000000000 if x & 0xffffffffffffffff > 0x7fffffffffffffff else x & 0xffffffffffffffff

    r = [0] * 344
    r[0] = s

    for i in range(1, 31):
        r[i] = int32(int64(16807 * r[i - 1]) % 0x7fffffff)

        if r[i] < 0:
            r[i] = int32(r[i] + 0x7fffffff)

    for i in range(31, 34):
        r[i] = int32(r[i - 31])

    for i in range(34, 344):
        r[i] = int32(r[i - 31] + r[i - 3])

    i = 344 - 1

    while True:
        i += 1
        r.append(int32(r[i - 31] + r[i - 3]))
        yield int32((r[i] & 0xffffffff) >> 1)


def get_guess(states):
    assert len(states) >= 32, "Only guess with at least 32 previous states"

    s_31 = states[-31]
    s_3 = states[-3]

    guess = (s_31 + s_3) % (1 << 31)
    
    return guess


# glibc initial values
modulus = 2 ** 31
multiplier = 1_103_515_245
increment = 12_345
# modulus = 3187
# multiplier = 2663
# increment = 1234

seed = random.randint(0, modulus)
rng = glibc_prng(s=seed)

init_states = []
init_size = 3

iterations = 0

for _ in range(init_size):
    init_states.append(next(rng))

hits = 0
fails = 0
guess = 0

previous_states = init_states

try:
    for r in rng:
        guess = get_guess(previous_states)
        previous_states.append(r)
        if guess == r:
            hits += 1
        else:
            fails += 1

except KeyboardInterrupt:
    print(f'''
Total hits: {hits}
Total fails: {fails}

Hit probability = {(hits / (hits+fails)) * 100}%''')
