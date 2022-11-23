from challenge2 import byte_xor

def repeating_key_xor(x, key):
    quotient = len(x) // len(key)
    modulus = len(x) % len(key)

    padded_key = key * quotient + key[:modulus]

    return byte_xor(x, padded_key).hex()


if __name__ == "__main__":
    x = repeating_key_xor(b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal""", b"ICE")

    print(x)
