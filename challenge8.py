import base64
from challenge6 import chunk

def is_ecb(ciphertext):
    blocks = list(chunk(ciphertext, 16))
    return len(blocks) != len(set(blocks))

if __name__ == '__main__':
    with open('./data/c8.txt') as file:
        for line in file:
            s = bytes.fromhex(line)

            if is_ecb(s):
                print("YES", s)

