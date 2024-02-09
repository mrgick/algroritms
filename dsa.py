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


def generate_params(hash: int) -> tuple[int, int, int]:
    return 11, 23, 4
    # Big nums, very slow
    N = len(bin(hash)[2:])
    q = int("1" + "0" * (N - 1), 2)
    p = q + 1
    g = 4
    return q, p, g


def main():
    text = input("Enter message: ")
    hash = int(sha_256(text), 16)
    print(f"hash = {hash}")

    q, p, g = generate_params(hash)
    print(f"q = {q} p = {p} g = {g}")

    x = random.randint(1, q)
    y = pow(g, x) % p

    print(f"Secret key = {x}\nPublic key = {y}")

    r, s = dsa_sign(q, p, g, x, hash)
    print(f"r = {r}, s = {s}")
    verify = dsa_verify(r, s, g, q, p, y, hash)
    if verify:
        print("Good sign!")
    else:
        print("Bad sign!")


if __name__ == "__main__":
    main()
