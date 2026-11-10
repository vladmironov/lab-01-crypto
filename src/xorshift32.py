import hashlib

def init_seed(key: bytes):
    dig = hashlib.sha256(key).digest()
    seed = int.from_bytes(dig[:4], 'big')
    if seed != 0:
        return seed
    else:
        return 1

mask = 0xFFFFFFFF

class xorshift:
    def __init__(self, seed: int):
        if seed == 0:
            seed = 1
        self.state = seed & mask

    def next(self):
        x = self.state
        x ^= (x << 13) & mask
        x ^= (x >> 17)
        x ^= (x << 5) & mask
        self.state = x & mask
        return self.state

def get_key(seed: int, length: int):
    gen = xorshift(seed)
    out = bytearray()

    while len(out) < length:
        word = gen.next()
        out.extend(word.to_bytes(4, 'big'))
    
    return bytes(out[:length])

def xor_crypt(data: bytes, key: bytes):
    seed = init_seed(key)
    ks = get_key(seed, len(data))

    final = bytearray()
    for i in range(len(data)):
        final.append(data[i] ^ ks[i])
    return bytes(final)

## Быстрые проверки
'''
if __name__ == "__main__":
    key = b"my-secret-key"
    msg = b"Hello, World! Test message for XOR stream cipher, 1234567890."

    ct = xor_crypt(msg, key)
    pt = xor_crypt(ct, key)

    print("plain :", msg)
    print("cipher:", ct.hex())
    print("back  :", pt)
    print("len ok:", len(ct) == len(msg))
    print("round-trip ok:", pt == msg)

'''