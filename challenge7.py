import base64
from Crypto.Cipher import AES

def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

if __name__ == '__main__':
    with open('./data/c7.txt') as file:
        s = base64.b64decode(file.read())
        print(aes_ecb_decrypt(s, b"YELLOW SUBMARINE"))

