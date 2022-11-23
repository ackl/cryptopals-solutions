import secrets
import random
from challenge10 import aes_ecb_encrypt, aes_cbc_encrypt
from challenge9 import pkcs_pad
from challenge6 import chunk

def generate_key():
    return get_rand_bytes(16)

def get_rand_bytes(bytes_):
    return secrets.randbits(bytes_ * 8).to_bytes(bytes_, 'big')

def pad_with_rand(plaintext):
    pad = get_rand_bytes(random.randint(5, 10))
    return pad + plaintext + pad

def encryption_oracle(plaintext, use_ecb = None):
    if use_ecb == None:
        use_ecb = random.randint(0, 1)

    padded_plaintext = pad_with_rand(plaintext)

    if use_ecb:
        return aes_ecb_encrypt(pkcs_pad(padded_plaintext, 16), generate_key())
    else:
        return aes_cbc_encrypt(padded_plaintext, generate_key(), generate_key())

def is_ecb(ciphertext):
    blocks = list(chunk(ciphertext, 16))
    return len(blocks) != len(set(blocks))

if __name__ == '__main__':
    s = b'X' * 54

    modes = [bool(random.randint(0,1)) for i in range(10)]
    detected = [is_ecb(encryption_oracle(s, mode)) for mode in modes]
    
    print(modes)
    print(detected)
    print(modes == detected)

