## Лабораторная работа 1. Теоретическая часть

Сегодня на расмотрении алгоритмы криптографического шифрования AES-ECB, AES-CTR и базовый алгоритм на основе XOR.

**AES** — симметричный блочный шифр: шифрует данные блоками по 128 бит с ключом 128, 192 или 256 бит. Широко используется для защиты данных.

Конкретно в нашей работе рассматриваются 2 варианта AES:
- ECB-алгоритм (128-битный блок шифруется независимо одним и тем же ключом)
- CTR-алгоритм ( шифруются последовательные значения счётчика (с nonce), результат XOR-ится с данными)

**XOR** - простейший симметричный метод: каждый бит/байт открытого текста складывается по модулю 2 (XOR) с соответствующим битом/байтом ключа (или гаммы). Шифрование и расшифрование — одна и та же операция

Начнем разбор с влгоритма **XOR**

Первое, что мы сделали - написали класс xorshift32 как исходный генератор псевдосллучайной последовательности. Ознакомиться вы с ним можно в папке пректа **/src/xorshift32.py**

В данном классе все реализуется в блоках ''\_\_init\_\_'' и ''next''. Все основываетсяна двух операциях:
- Побитовый сдвиг влево/вправо (>> и << соответственно)
- Операция XOR (побитовое исключающее ''или'')

```python
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
```

Остальной же код - это шифрование/дешифрование исходного сообщения. Для проверки вы можете раскомментировать следующие строки в коде 

```python
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
```

Теперь к алгоритму **AES**

Реализация данного алгоритма выполняется с помощью библиотеки **pycryptodome**. Инструкции к ее уccтановке представлены в README.md

Сам код программы будет выглядеть так:

**1. Импорт библиотек**

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
```

**Важно:** мы использовали Crypto.~, так как он является частью библиотеки pycryptodome

**2. Шифрование/дешифрование по AES-ECB**

```python
def aes_ecb_encrypt(plain: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plain, AES.block_size))

def aes_ecb_decrypt(ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
```

**3. Шифрование/дешифрование по AES-CTR**

```python
def aes_ctr_encrypt(plain: bytes, key: bytes, nonce: bytes = None):
    if nonce is None:
        nonce = get_random_bytes(8) 
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plain)
    return ciphertext, nonce

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)
```

После этого мы реализовывем 2 программы - **metrics.py** для вычисления горизонтальной и вертикальной корелляции, и **main.py** - основная программа. С ними вы можете ознакомиться внутри проекта



