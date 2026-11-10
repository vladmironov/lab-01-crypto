import json
import os
import numpy as np
from PIL import Image

from xorshift32 import xor_crypt
from aes import aes_ecb_encrypt, aes_ecb_decrypt, aes_ctr_encrypt, aes_ctr_decrypt
from metrics import calculate_entropy, calculate_correlation, plot_histograms, calculate_npcr_uaci

def main():
    os.makedirs("results", exist_ok=True)
    os.makedirs("recover", exist_ok=True)
    os.makedirs("encrypted", exist_ok=True)

    meta_path = "meta.json"

    with open(meta_path, "r", encoding="utf-8") as f:
        meta_data = json.load(f)
        
    meta_data["nonce"] = os.urandom(8).hex()

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=4)

    algorithm = meta_data.get("algorithm", "aes-ctr")
    source_img = meta_data.get("source", "gradient.png")
    nonce = bytes.fromhex(meta_data["nonce"])

    img_path = f"img/{source_img}"

    if not os.path.exists(img_path):
        print(f"Ошибка: Файл {img_path} не найден!")
        return

    img = Image.open(img_path).convert("RGB")
    img_array = np.array(img)
    original_bytes = img_array.tobytes()
    shape = img_array.shape

    xor_key = b"my-secret-xor-key"
    aes_key = b"0123456789abcdef"

    print(f"Алгоритм из meta.json: {algorithm}")
    print(f"Исходный файл: {source_img}")
    print()

    if algorithm == "xor":
        ct_main = xor_crypt(original_bytes, xor_key)
        pt_main = xor_crypt(ct_main, xor_key)
        ct_len = len(ct_main)
        key_2 = bytearray(xor_key)
    elif algorithm == "aes-ecb":
        ct_main = aes_ecb_encrypt(original_bytes, aes_key)
        pt_main = aes_ecb_decrypt(ct_main, aes_key)
        ct_len = len(original_bytes)
        key_2 = bytearray(aes_key)
    elif algorithm == "aes-ctr":
        ct_main, _ = aes_ctr_encrypt(original_bytes, aes_key, nonce=nonce)
        pt_main = aes_ctr_decrypt(ct_main, aes_key, nonce)
        ct_len = len(ct_main)
        key_2 = bytearray(aes_key)
    else:
        print(f"Ошибка: Неизвестный алгоритм {algorithm}")
        return

    print(f"Обратимость: {original_bytes == pt_main}")
    
    Image.fromarray(np.frombuffer(ct_main[:ct_len], dtype=np.uint8).reshape(shape)).save(f"encrypted/encrypted_{algorithm}.png")
    Image.fromarray(np.frombuffer(pt_main, dtype=np.uint8).reshape(shape)).save(f"recover/recovered_{algorithm}.png")

    print(f"\n{algorithm.upper()}")
    
    print("\n1. Энтропия")
    print(f"Оригинал: {calculate_entropy(original_bytes):.4f}")
    print(f"{algorithm.upper()}: {calculate_entropy(ct_main[:ct_len]):.4f}")

    print("\n2. Корреляция")
    print(f"Оригинал: {calculate_correlation(img_array):.4f}")
    
    arr_main = np.frombuffer(ct_main[:ct_len], dtype=np.uint8).reshape(shape)
    print(f"{algorithm.upper()}: {calculate_correlation(arr_main, 'horizontal'):.4f}")
    print(f"{algorithm.upper()}: {calculate_correlation(arr_main, 'vertical'):.4f}")

    print("\n3. Построение гистограмм...")
    plot_histograms({
        "Оригинал": original_bytes,
        algorithm.upper(): ct_main[:ct_len]
    }, filename=f"results/histograms_{algorithm}.png")

    print(f"\n4. NPCR/UACI для {algorithm.upper()}")
    key_2[0] ^= 0x01 
    key_2 = bytes(key_2)

    if algorithm == "xor":
        ct_main_2 = xor_crypt(original_bytes, key_2)
    elif algorithm == "aes-ecb":
        ct_main_2 = aes_ecb_encrypt(original_bytes, key_2)
    elif algorithm == "aes-ctr":
        ct_main_2, _ = aes_ctr_encrypt(original_bytes, key_2, nonce=nonce)
    
    npcr, uaci = calculate_npcr_uaci(ct_main[:ct_len], ct_main_2[:ct_len])
    print(f"NPCR: {npcr:.2f}%")
    print(f"UACI: {uaci:.2f}%")

if __name__ == "__main__":
    main()