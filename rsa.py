from collections.abc import Generator
from dataclasses import dataclass
from math import gcd
import secrets

sys_random = secrets.SystemRandom()


@dataclass
class PrivateKey:
    n: int
    d: int


@dataclass
class PublicKey:
    n: int
    e: int


class MessageLengthError(Exception): ...


def is_prime(n: int, iterations: int) -> bool:
    """True if n is prime"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True

    # n-1 = 2^k * m
    n1: int = n - 1
    k: int = 0

    while n1 % 2 == 0:
        n1 //= 2
        k += 1

    m = (n - 1) // (2**k)

    a = sys_random.randint(2, n - 2)
    b = pow(a, m, n)

    if b == 1 or b == n - 1:
        return True

    for _ in range(iterations):
        b = pow(b, 2, n)

        if b == 1:
            return False
        if b == n - 1:
            return True

    return False


def __prime_candidates(length: int) -> Generator[int]:
    """generates candidates for prime numbers (odd, MSB is 1)"""
    while True:
        candidate: int = secrets.randbits(length)
        candidate |= (1 << (length - 1)) | 1
        yield candidate


def generate_prime(length: int) -> int:
    """generate a prime with less or equal bitlength"""
    for candidate in __prime_candidates(length):
        if is_prime(candidate, 64):
            return candidate
    raise Exception("This should not happen, I did it so pyright won't curse at me")


def generate_key_pair(
    nlen: int = 2048, e: int = 0x10001
) -> tuple[PrivateKey, PublicKey]:
    """generates a public and private key for rsa"""
    while True:
        p: int = generate_prime(nlen // 2)
        q: int = generate_prime(nlen // 2)
        n: int = p * q

        phi: int = (p - 1) * (q - 1)

        if gcd(phi, e) == 1:
            break

    d: int = pow(e, -1, phi)

    return PrivateKey(n, d), PublicKey(n, e)


def encode(message: int, public_key: PublicKey) -> int:
    """encode a message using RSA"""
    if public_key.n <= message:
        raise MessageLengthError("the message must be less then n")

    return pow(message, public_key.e, public_key.n)


def decode(cypher: int, private_key: PrivateKey) -> int:
    """decode a RSA cypher"""
    return pow(cypher, private_key.d, private_key.n)
