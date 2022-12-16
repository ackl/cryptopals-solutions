from challenge6 import chunk

def strip_pkcs_padding(s):
    if type(s) != bytes:
        s = bytes(s, 'utf-8')

    blocks = list(chunk(s, 16))

    padding_block = blocks[-1]

    if len(padding_block) != 16:
        raise Exception('padding invalid')

    last_byte = padding_block[-1]

    if last_byte not in range(1, 17):
        raise Exception('padding invalid')

    test_padding = last_byte.to_bytes(1, byteorder='big') * last_byte

    if padding_block != test_padding:
        raise Exception('padding invalid')

    return b''.join(blocks[:-1])
