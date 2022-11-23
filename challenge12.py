import base64
from challenge11 import generate_key
from challenge10 import aes_ecb_encrypt, aes_cbc_encrypt
from challenge9 import pkcs_pad
from challenge6 import chunk

# global_key = generate_key()
global_key = b'd\xb7t9\x07\xbb9\xdf\x85\xa4\xc7w\x9e\xe2\xda\x96'

unknown = base64.b64decode(b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK''')

def aes_ecb_encrypt_consistent_key(plaintext):
    return aes_ecb_encrypt(pkcs_pad(plaintext + unknown, 16), global_key)

def find_next_byte(decrypted_flag):
    block_size = 16
    decrypted_length = len(decrypted_flag)

    # will go from blocksize - 1 down to 0 as we fill up the block
    # with more and more 'known' bytes
    padding = b"X" * (-(decrypted_length + 1) % block_size)

    target_block_idx = decrypted_length // block_size
    ciphertext = aes_ecb_encrypt_consistent_key(padding)
    target_block = list(chunk(ciphertext, block_size))[target_block_idx]

    for i in range(256):
        message = padding + decrypted_flag + bytes([i])
        candidate_ciphertext = aes_ecb_encrypt_consistent_key(message)
        candidate_block = list(chunk(candidate_ciphertext, block_size))[target_block_idx]
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
