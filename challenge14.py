import base64
import random
from challenge12 import find_next_byte
from challenge11 import generate_key, get_rand_bytes
from challenge10 import aes_ecb_encrypt, aes_cbc_encrypt
from challenge9 import pkcs_pad
from challenge6 import chunk

global_key = generate_key()

unknown = base64.b64decode(b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK''')

def get_random_prefix():
    return get_rand_bytes(random.randint(0, 16))

random_prefix = get_random_prefix()

def aes_ecb_encrypt_random_prefix(plaintext):
    return aes_ecb_encrypt(pkcs_pad(random_prefix + plaintext + unknown, 16), global_key)

def find_next_byte(decrypted_flag):
    block_size = 16
    decrypted_length = len(decrypted_flag)

    # will go from blocksize - 1 down to 0 as we fill up the block
    # with more and more 'known' bytes
    padding = b"X" * (-(decrypted_length + 1 + len(random_prefix)) % block_size)

    target_block_idx = (decrypted_length + len(random_prefix)) // block_size
    ciphertext = aes_ecb_encrypt_random_prefix(padding)
    target_block = list(chunk(ciphertext, block_size))[:target_block_idx + 1]

    for i in range(256):
        message = padding + decrypted_flag + bytes([i])
        candidate_ciphertext = aes_ecb_encrypt_random_prefix(message)
        candidate_block = list(chunk(candidate_ciphertext, block_size))[:target_block_idx + 1]
        if candidate_block == target_block:
            return bytes([i])


def find_flag():
    decrypted_flag = b""

    for i in range(138):
        next_byte = find_next_byte(decrypted_flag)
        decrypted_flag = decrypted_flag + next_byte

    return decrypted_flag


if __name__ == '__main__':
    a = find_flag()
    print(a)
