from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

## ECB и CTR

def aes_ecb_encrypt(plain: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plain, AES.block_size))

def aes_ecb_decrypt(ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def aes_ctr_encrypt(plain: bytes, key: bytes):
    nonce = get_random_bytes(8) # 8 байт nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plain)
    return ciphertext, nonce

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)