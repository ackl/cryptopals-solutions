def byte_xor(x, y):
    return bytes([a ^ b for a, b in zip(x, y)])

def fixed_xor(x, y):
    return byte_xor(bytes.fromhex(x), bytes.fromhex(y)).hex()

if __name__ == "__main__":
    x = fixed_xor(
        '1c0111001f010100061a024b53535009181c',
        '686974207468652062756c6c277320657965'
    )

    print(x)
