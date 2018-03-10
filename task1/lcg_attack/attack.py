import random
from math import gcd
from functools import reduce


def lcg(m, a, c, s):
    while True:
        s = (a * s + c) % m
        yield s

def extended_gcd(b, n):
    x, lx = 1, 0
    y, ly = 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x, lx = lx, x - q*lx
        y, ly = ly, y - q*ly
    return b, x, y


def mod_inv(b, n):
    g, x, _ = extended_gcd(b, n)
    if g != 1:
        raise ValueError('%i and %i are not relatively prime numbers, divider is %i' % (b, n, g))
    return x % n

def get_guess(states):
    # states: ..., s_5, s_4, s_3, s_2, s_1, guess

    # use at most 64 previous values
    n = min(16, len(states))
    n_1 = n - 1

    # diff_0 = s_4 - s_5
    # diff_1 = s_3 - s_4 = (s_4 * mult + inc) - (s_5 * mult + inc) = mult * (s_4 - s_5) = mult * diff_0  (mod modulus)
    # diff_2 = s_2 - s_3 = (s_3 * mult + inc) - (s_4 * mult + inc) = mult * (s_3 - s_4) = mult * diff_1  (mod modulus)
    # diff_3 = s_1 - s_2 = (s_2 * mult + inc) - (s_3 * mult + inc) = mult * (s_2 - s_3) = mult * diff_2  (mod modulus)
    diffs = [s_i - s_j for s_i, s_j in zip(states[-1*n_1:], states[-1*n:-1])]

    # zero_0
    # = diff_2*diff_0 - diff_1*diff_1
    # = (mult*mult*diff_0 * diff_0) - (mult*diff_0 * mult*diff_0)
    # = 0  (mod modulus)
    # zero_1
    # = diff_3*diff_1 - diff_2*diff_2
    # = (mult*mult*diff_1 * diff_1) - (mult*diff_1 * mult*diff_1) 
    # = 0  (mod modulus)
    zeroes = [diff_k*diff_i - diff_j*diff_j for diff_i, diff_j, diff_k in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))

    # s_1 = s_2*mult + inc  (mod modulus)
    # s_2 = s_3*mult + inc  (mod modulus)
    # s_3 = s_4*mult + inc  (mod modulus)
    # s_4 = s_5*mult + inc  (mod modulus)

    # s_1 - s_2 = (s_2*mult + inc) - (s_3*mult + inc) = s_2*mult - s_3*mult = mult*(s_2 - s_3)  (mod modulus)
    # mult = (s_1 - s_2)/(s_2 - s_3)  (mod modulus)
    multiplier = (states[-1] - states[-2]) * mod_inv(states[-2] - states[-3], modulus) % modulus

    # s_1 = s_2*mult + inc  (mod modulus)
    # inc = s_1 - s_2*mult  (mod modulus)
    increment = (states[-1] - (states[-2]*multiplier)) % modulus
    
    return (multiplier * states[-1] + increment) % modulus

# glibc initial values
modulus = 2 ** 31
multiplier = 1_103_515_245
increment = 12_345
# modulus = 3187
# multiplier = 2663
# increment = 1234

seed = random.randint(0, modulus)

rng = lcg(m=modulus, a=multiplier, c=increment, s=seed)

init_states = []
init_size = 10

iterations = 0

for _ in range(init_size):
    init_states.append(next(rng))

hits = 0
fails = 0
guess = 0
previous_states = init_states

try:
    for r in rng:
        try:
            guess = get_guess(previous_states)
            if guess == r:
                hits += 1
            else:
                raise ValueError("Your guess was wrong!")
        except ValueError:
            fails += 1
        previous_states.append(r)

except KeyboardInterrupt:
    print(f'''
Total hits: {hits}
Total fails: {fails}

Hit probability = {(hits / (hits+fails)) * 100}%''')
