import struct
H = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
def ROTR(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def SHR(x, n):
    return x >> n

def Ch(x, y, z):
    return (x & y) ^ (~x & z)

def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0(x):
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)

def Sigma1(x):
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)

def sigma0(x):
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)

def sigma1(x):
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)

def pad_message(message_bytes):
    ml = len(message_bytes) * 8 
    message_bytes += b'\x80'  
    while (len(message_bytes) * 8) % 512 != 448:
        message_bytes += b'\x00'
    message_bytes += struct.pack(">Q", ml) 
    return message_bytes


def sha256(message):
    message_bytes = message.encode() if isinstance(message, str) else message
    message_bytes = pad_message(message_bytes)

    
    H_copy = H.copy()

    
    for i in range(0, len(message_bytes), 64):
        block = message_bytes[i:i+64]

       
        W = list(struct.unpack(">16L", block))  # первые 16 слов
        for t in range(16, 64):
            val = (sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]) & 0xFFFFFFFF
            W.append(val)

        
        a, b, c, d, e, f, g, h_var = H_copy

      
        for t in range(64):
            T1 = (h_var + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]) & 0xFFFFFFFF
            T2 = (Sigma0(a) + Maj(a,b,c)) & 0xFFFFFFFF
            h_var = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF

        
        H_copy = [
            (H_copy[0] + a) & 0xFFFFFFFF,
            (H_copy[1] + b) & 0xFFFFFFFF,
            (H_copy[2] + c) & 0xFFFFFFFF,
            (H_copy[3] + d) & 0xFFFFFFFF,
            (H_copy[4] + e) & 0xFFFFFFFF,
            (H_copy[5] + f) & 0xFFFFFFFF,
            (H_copy[6] + g) & 0xFFFFFFFF,
            (H_copy[7] + h_var) & 0xFFFFFFFF
        ]

    
    return ''.join(f'{x:08x}' for x in H_copy)


if __name__ == "__main__":
    message=input("Enter message baby: ")
    print(f"SHA-256('{message}') =", sha256(message))