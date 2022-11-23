import base64

def convert_hex_to_b64(hex_string):
    return base64.b64encode(bytes.fromhex(hex_string)).decode()

if __name__ == "__main__":
    x = convert_hex_to_b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')

    print(x)
