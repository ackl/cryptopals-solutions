import urllib.parse
from challenge11 import generate_key
from challenge10 import aes_cbc_decrypt, aes_cbc_encrypt
from challenge9 import pkcs_pad
from challenge6 import chunk

# global_key = generate_key()
# global_iv = generate_key()
global_key = b'\x15\\\xa0\xd4\x8afw\x81\xe8\x8e 3a\x04\xea\\'
global_iv = b'\xe4OO\xc4\xed\x08\x17:#""\xe7\xc7OUe'
target_substring = ';admin=true;'

def encrypt_cookie(userdata):
    prepend = 'comment1=cooking%20MCs;userdata='
    append = ';comment2=%20like%20a%20pound%20of%20bacon'

    plaintext = prepend + urllib.parse.quote(userdata) + append

    return aes_cbc_encrypt(plaintext.encode(), global_key, global_iv)

def has_admin(ciphertext):
    plaintext = aes_cbc_decrypt(ciphertext, global_key, global_iv)
    print(plaintext)

    return target_substring.encode() in plaintext


if __name__ == '__main__':
    s = encrypt_cookie('x' * 12)
    blocks = list(chunk(s, 16))

    flip_bytes = bytearray()

    for idx, char in enumerate(target_substring):
        target = ord(char)

        for i in range(256):
            candidate_byte = (i).to_bytes(1, 'big')
            block_1 = bytearray(blocks[1])

            block_1[idx] = i

            modified_cipher = b''.join([blocks[0], bytes(block_1)] + blocks[2:])
            modified_plaintext = aes_cbc_decrypt(modified_cipher, global_key, global_iv)
            chunks = list(chunk(modified_plaintext, 16))

            if chunks[2][idx] == target:
                flip_bytes.append(i)
                break

    block_1 = bytearray(blocks[1])
    blocks[1] = bytes(flip_bytes) + blocks[1][len(target_substring):]
    print(has_admin(b''.join(blocks)))
