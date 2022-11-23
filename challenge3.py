import string
from challenge2 import byte_xor

ords = [ord(x) for x in string.ascii_letters + ' ']

def single_byte_xor(x, xor_char):
    x_ = bytes.fromhex(x)

    return byte_xor(x_, bytes([xor_char] * len(x_))).hex()

def predict_key(x):
    d = {}

    for byte_candidate in range(256):
        xorred_bytes = bytes.fromhex(single_byte_xor(x, byte_candidate))

        d[byte_candidate] = 0

        for c in xorred_bytes:
            if c in ords:
                d[byte_candidate] += 1

    key = max(d, key=d.get)

    return (key, bytes.fromhex(single_byte_xor(x, key)))

if __name__ == "__main__":
    x = predict_key('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    print(x)
