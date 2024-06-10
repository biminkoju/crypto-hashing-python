import sys
import hashlib
import math


#bit rotating function thing
def ROTR(x, n):
    return ((x >> n) | (x << (32-n))) & 0xFFFFFFFF

def SHA_256(s):
    kSHA256Constants = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    def Ch(x, y, z):
        return (x & y) ^ (~x & z)

    def Maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def Sigma0(x):
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)

    def Sigma1(x):
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)

    def sigma0(x):
        return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3)

    def sigma1(x):
        return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10)

    def sha256_block(block, H):
        W = [0]*64
        for t in range(16):
            W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] <<
                                           16) | (block[t * 4 + 2] << 8) | block[t * 4 + 3]
        for i in range(16, 64):
            W[i] = (sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16]) & 0xFFFFFFFF
        a, b, c, d, e, f, g, h = H
        for j in range(64):
            T1 = h + Sigma1(e) + Ch(e, f, g) + kSHA256Constants[j] + W[j]
            T2 = Sigma0(a) + Maj(a, b, c)
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF

        H[0] = (H[0] + a) & 0xFFFFFFFF
        H[1] = (H[1] + b) & 0xFFFFFFFF
        H[2] = (H[2] + c) & 0xFFFFFFFF
        H[3] = (H[3] + d) & 0xFFFFFFFF
        H[4] = (H[4] + e) & 0xFFFFFFFF
        H[5] = (H[5] + f) & 0xFFFFFFFF
        H[6] = (H[6] + g) & 0xFFFFFFFF
        H[7] = (H[7] + h) & 0xFFFFFFFF

    s = bytearray(s, 'utf-8')
    length = len(s) * 8
    s.append(0x80)
    while (len(s) * 8) % 512 != 448:
        s.append(0)
    s += length.to_bytes(8, 'big')

    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    for i in range(0, len(s), 64):
        sha256_block(s[i:i+64], H)

    return ''.join(f'{x:08x}' for x in H)

def MD5(s):
    S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    K = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    s=bytearray(s,'utf-8')

    def md5_padding(s):
        original_length = len(s) * 8
        s += b'\x80'
        while len(s) % 64 != 56:
            s += b'\x00'
        s += original_length.to_bytes(8, 'little')
        return s

    def md5_process_chunk(chunk, a, b, c, d):
        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16

            temp = d
            d = c
            c = b
            b = (b + ROTR((a + f + K[i] + int.from_bytes(chunk[g * 4: (g + 1) * 4], 'little')) & 0xFFFFFFFF, S[i])) & 0xFFFFFFFF
            a = temp

        return a, b, c, d

    s = md5_padding(s)
    for i in range(0, len(s), 64):
        chunk = s[i:i + 64]
        A, B, C, D = md5_process_chunk(chunk, A, B, C, D)

    hash_value = A.to_bytes(4, 'little') + B.to_bytes(4, 'little') + C.to_bytes(4, 'little') + D.to_bytes(4, 'little')
    return hash_value.hex()

def SHA1(s):
    return hashlib.sha1(s.encode()).hexdigest()


def main():
    hashes = ["1", "2", "3", "4", "SHA1", "SHA_256", "MD5"]
    print('''
    hashing algorithims:
        1) SHA0
        2) SHA_256
        3) MD5
          ''')
    algoToUse = input("which hashing algo would you like to use?: ").lower()
    if algoToUse not in hashes:
        sys.exit("no correct hashing also provided")
    toHashString = input("enter your string to be hashed: ")
    if algoToUse == "1" or algoToUse == "sha1":
        print(f"Hashed string: {SHA1(toHashString)}")
    if algoToUse == "2" or algoToUse == "sha_256":
        print(f"Hashed string: {SHA_256(toHashString)}")
    if algoToUse == "3" or algoToUse == "md5":
        print(f"Hashed string: {MD5(toHashString)}")


if __name__ == "__main__":
    main()
