from sha2 import sha_256
import random


def euclid_ext(a, b):
    if b == 0:
        return a, 1, 0
    else:
        d, x, y = euclid_ext(b, a % b)
        return d, y, x - y * (a // b)


def dsa_sign(q: int, p: int, g: int, x: int, hash: int) -> tuple[int, int]:
    while True:
        k = random.randint(2, q)
        r = (g**k % p) % q
        if not r:
            continue
        s = (euclid_ext(k, q)[1] * (hash + x * r)) % q
        if not s:
            continue
        return int(r), int(s)


def dsa_verify(r: int, s: int, g: int, q: int, p: int, y: int, hash: int) -> bool:
    w = euclid_ext(s, q)[1]
    u1 = (hash * w) % q
    u2 = (r * w) % q
    v = (g**u1 * y**u2 % p) % q
    return v == r


def main():
    text = "hello world"
    hash = sha_256(text)
    num_hash = int(hash, 16)
    # N = len(bin(num_hash)[2:])
    # q = int("1" + "0" * (N - 1), 2)

    # p = q + 1
    # L = len(bin(p)[2:])
    # print(f"L={L}, N={N}")

    g = 4

    q = 11
    p = 23
    g = 4

    x = 7  # secret key
    y = pow(g, x) % p  # public key
    print(f"Secret key = {x}\nPublic key = {y}")
    r, s = dsa_sign(q, p, g, x, num_hash)
    print(r, s)
    l = dsa_verify(r, s, g, q, p, y, num_hash)
    print(l)


if __name__ == "__main__":
    main()
