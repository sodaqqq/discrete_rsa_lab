from dataclasses import dataclass
from math import gcd


@dataclass
class PrivateKey:
    n: int
    d: int


@dataclass
class PublicKey:
    n: int
    e: int


class MessageLengthError(Exception): ...


def generate_prime(length: int) -> int:
    """generate a prime with less or equal bitlength"""
    raise NotImplementedError


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
