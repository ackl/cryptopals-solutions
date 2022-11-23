import base64
from Crypto.Cipher import AES
from challenge9 import pkcs_pad
from challenge7 import aes_ecb_decrypt
from challenge6 import chunk
from challenge2 import byte_xor

def aes_ecb_encrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(ciphertext)

def aes_cbc_encrypt(plaintext, key, iv):
    # pad plaintext so its length is multiple of 16 bytes 
    # then chunk it into 16 byte blocks
    blocks = list(chunk(pkcs_pad(plaintext, 16), 16))

    # use initialisation vector as first previous cipherblock
    prev_cipherblock = iv

    result = b''

    for block in blocks:
        xord = byte_xor(prev_cipherblock, block)
        prev_cipherblock = aes_ecb_encrypt(xord, key)
        result += prev_cipherblock

    return result

def aes_cbc_decrypt(ciphertext, key, iv):
    blocks = list(chunk(ciphertext, 16))
    prev_cipherblock = iv

    result = b''

    for block in blocks:
        decrypted = aes_ecb_decrypt(block, key)
        xord = byte_xor(prev_cipherblock, decrypted)
        prev_cipherblock = block
        result += xord

    return result


if __name__ == '__main__':
    s = b'the industrial revolution and its consequences have been a disaster for the human race'
    key = b'YELLOW SUBMARINE'

    a = aes_cbc_encrypt(s, key, bytes(16))
    print(a)

    b = aes_cbc_decrypt(a, key, bytes(16))
    print(b)

    with open('./data/c10.txt') as file:
        s = base64.b64decode(file.read())
        c = aes_cbc_decrypt(s, key, bytes(16))
        print(c)
