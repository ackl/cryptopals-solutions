def pkcs_pad(block, length): 
    block_size = len(block)
    padding_length = length - (block_size % length)

    return block + bytes([padding_length] * padding_length)
