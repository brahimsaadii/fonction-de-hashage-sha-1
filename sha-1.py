import struct

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def preprocess_message(message):
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8

    message += b'\x80'

    while len(message) % 64 != 56:
        message += b'\x00'

    message += struct.pack('>Q', original_bit_len)

    return message

def sha1(message):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    message = preprocess_message(message)

    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]
        words = list(struct.unpack('>16I', chunk))

        for j in range(16, 80):
            words.append(left_rotate(words[j - 3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16], 1))

        a, b, c, d, e = h0, h1, h2, h3, h4

        for j in range(80):
            if 0 <= j < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + words[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

# Exemple d'utilisation
message = "hello.friend"
hashed_message = sha1(message.encode('utf-8'))
print(f"Message: {message}")
print(f"Hachage SHA-1: {hashed_message}")

# comparaison avec sha-1 predefini 
import hashlib

def sha1_hash(input_string):
    sha1 = hashlib.sha1()
    sha1.update(input_string.encode('utf-8'))
    return sha1.hexdigest()

print(sha1_hash(message))
print(sha1_hash(message) == hashed_message)
