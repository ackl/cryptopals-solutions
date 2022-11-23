import base64
from challenge2 import byte_xor
from challenge3 import predict_key, ords
from challenge5 import repeating_key_xor

# bit level hamming distance
def hamming_distance(a, b):
    xor = int(a.hex(), 16) ^ int(b.hex(), 16)
    return bin(xor).count('1')

def test_data():
    d = {}

    with open('./data/c6.txt') as file:
        raw_data = base64.b64decode(file.read())
        
        for key_size in range(2, 41):
            blocks = get_blocks(raw_data, key_size)

            samples = len(blocks)
            # if length is odd, minus one from no. of samples
            # to avoid out of index when we try to access index i+1 below
            if samples % 2:
                samples -= 1

            score = 0

            for i in range(0, samples, 2):
                score += hamming_distance(blocks[i], blocks[i+1])

            score /= key_size
            score /= samples

            d[key_size] = score

        candidate_key_size = min(d, key=d.get)
        blocks = get_blocks(raw_data, candidate_key_size)

        transposed = [[b[i] for b in blocks] for i in range(candidate_key_size)]

        candidate_key = []
        for t in transposed:
            (key_byte, _) = predict_key(bytes(t).hex())
            candidate_key.append(key_byte)

        print(bytes.fromhex(repeating_key_xor(raw_data, bytes(candidate_key))))

def get_blocks(lst, n):
    blocks = list(chunk(lst, n))
    blocks[-1] = blocks[-1].ljust(n, b'\0')
    return blocks

def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def decrypt(x, key):
    quotient = len(x) // len(key)
    modulus = len(x) % len(key)

    padded_key = key * quotient + key[:modulus]

    return byte_xor(x, padded_key)


if __name__ == "__main__":
    x = hamming_distance(b'this is a test', b'wokka wokka!!!')

    print(x)

    x = test_data()

