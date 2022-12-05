import re
from challenge11 import generate_key
from challenge10 import aes_ecb_encrypt, aes_ecb_decrypt
from challenge9 import pkcs_pad

global_key = generate_key()

def parse_query_string(s):
    ret = {}

    parts = s.split('&')

    for part in parts:
        [key, value] = part.split('=')
        ret[key] = value

    return ret

def profile_for(s):
    s = re.sub(r'[&=]', '', s)
    encoded_string = f'email={s}&uid=10&role=user'

    return encoded_string

def encrypted_profile_for(s):
    encoded_string = profile_for(s).encode()

    return aes_ecb_encrypt(pkcs_pad(encoded_string, 16), global_key)

def decrypt_profile(s):
    plaintext = aes_ecb_decrypt(s, global_key)

    return parse_query_string(plaintext.decode())
