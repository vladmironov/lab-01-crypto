import os
import numpy as np
from PIL import Image

from xorshift32 import xor_crypt
from aes import aes_ecb_encrypt, aes_ecb_decrypt, aes_ctr_encrypt, aes_ctr_decrypt
from metrics import calculate_entropy, calculate_correlation, plot_histograms, calculate_npcr_uaci

def main():
    os.makedirs("results", exist_ok=True)

    img_path = "imgs/gradient.png"
    if not os.path.exists(img_path):
        print(f"Ошибка: Файл {img_path} не найден. Создайте папку imgs и положите туда картинку.")
        return

    img = Image.open(img_path).convert("RGB")
    img_array = np.array(img)
    original_bytes = img_array.tobytes()

    xor_key = b"my-secret-xor-key"
    aes_key = b"0123456789abcdef"

    print("="*50)
    print("ШАГ 1: ШИФРОВАНИЕ")
    print("="*50)
    
    ct_xor = xor_crypt(original_bytes, xor_key)
    ct_ecb = aes_ecb_encrypt(original_bytes, aes_key)
    ct_ctr, nonce = aes_ctr_encrypt(original_bytes, aes_key)

    print("Данные успешно зашифрованы тремя методами.")

    print("\n" + "="*50)
    print("ШАГ 2: ПРОВЕРКА ОБРАТИМОСТИ")
    print("="*50)
    
    pt_xor = xor_crypt(ct_xor, xor_key)
    pt_ecb = aes_ecb_decrypt(ct_ecb, aes_key)
    pt_ctr = aes_ctr_decrypt(ct_ctr, aes_key, nonce)

    print(f"XOR восстановлен:  {original_bytes == pt_xor}")
    print(f"AES-ECB восстановлен: {original_bytes == pt_ecb}")
    print(f"AES-CTR восстановлен: {original_bytes == pt_ctr}")

    print("\n" + "="*50)

    print("ШАГ 3: СТАТИСТИЧЕСКИЕ МЕТРИКИ")
    print("="*50)
    
    print("--- Энтропия ---")
    print(f"Оригинал: {calculate_entropy(original_bytes):.4f}")
    print(f"XOR:      {calculate_entropy(ct_xor):.4f}")
    print(f"AES-ECB:  {calculate_entropy(ct_ecb):.4f}")
    print(f"AES-CTR:  {calculate_entropy(ct_ctr):.4f}")

    print("\n--- Корреляция (Horizontal) ---")

    shape = img_array.shape
    print(f"Оригинал: {calculate_correlation(img_array, 'horizontal'):.4f}")
    
    arr_xor = np.frombuffer(ct_xor, dtype=np.uint8).reshape(shape)
    print(f"XOR:      {calculate_correlation(arr_xor, 'horizontal'):.4f}")
    
    arr_ctr = np.frombuffer(ct_ctr, dtype=np.uint8).reshape(shape)
    print(f"AES-CTR:  {calculate_correlation(arr_ctr, 'horizontal'):.4f}")
    
    arr_ecb = np.frombuffer(ct_ecb[:len(original_bytes)], dtype=np.uint8).reshape(shape)
    print(f"AES-ECB:  {calculate_correlation(arr_ecb, 'horizontal'):.4f}")

    print("\n" + "="*50)
    print("ШАГ 4: ГИСТОГРАММЫ")
    print("="*50)
    plot_histograms({
        "Оригинал": original_bytes,
        "XOR": ct_xor,

        "AES-ECB": ct_ecb[:len(original_bytes)], 
        "AES-CTR": ct_ctr
    }, filename="results/histograms.png")
    print("Графики сохранены в results/histograms.png")

    print("\n" + "="*50)
    print("ШАГ 5: ЭКСПЕРИМЕНТ С КЛЮЧОМ (NPCR/UACI для AES-CTR)")
    print("="*50)

    aes_key_2 = bytearray(aes_key)
    aes_key_2[0] ^= 0x01 
    aes_key_2 = bytes(aes_key_2)

    ct_ctr_2, _ = aes_ctr_encrypt(original_bytes, aes_key_2)
    
    npcr, uaci = calculate_npcr_uaci(ct_ctr, ct_ctr_2)
    print(f"NPCR: {npcr:.2f}% (идеал ~99.6%)")
    print(f"UACI: {uaci:.2f}% (идеал ~33.4%)")

if __name__ == "__main__":
    main()