from challenge3 import predict_key, ords

def is_english_plaintext(x):
    return (sum([c in ords for c in x]) / len(x)) > 0.9

def detect_single_byte_xor():
    with open('./data/c4.txt') as file:
        for line in file:
            (k, candidate) = predict_key(line)

            if is_english_plaintext(candidate):
                print(line)
                print((k, candidate))


if __name__ == "__main__":
    detect_single_byte_xor()
