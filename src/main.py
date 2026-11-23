import csv
import hashlib
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

    with open("meta.json", "r", encoding="utf-8") as f:
        m = json.load(f)

    if "nonce" not in m:
        m["nonce"] = os.urandom(8).hex()
        with open("meta.json", "w", encoding="utf-8") as f:
            json.dump(m, f, indent=4)

    alg = m.get("algorithm", "aes-ctr")
    nr = bytes.fromhex(m["nonce"])

    xk = b"my-secret-xor-key"
    ak = b"0123456789abcdef"

    rs = []

    for src in ["gradient.png", "checkerboard.png"]:
        p = f"img/{src}"
        if not os.path.exists(p):
            print(f"Пропуск: {p} не найден")
            continue

        img = Image.open(p).convert("RGB")
        a = np.array(img)
        ob = a.tobytes()
        sh = a.shape
        st = src.replace(".png", "")

        n = hashlib.sha256(nr + src.encode()).digest()[:8] if alg == "aes-ctr" else None

        if alg == "xor":
            cf = xor_crypt(ob, xk)
        elif alg == "aes-ecb":
            cf = aes_ecb_encrypt(ob, ak)
        elif alg == "aes-ctr":
            cf, _ = aes_ctr_encrypt(ob, ak, nonce=n)
        else:
            print(f"Неизвестный алгоритм {alg}")
            return

        ci = cf[:len(ob)]

        bp = f"encrypted/{st}_{alg}.bin"
        with open(bp, "wb") as f:
            f.write(cf)

        Image.fromarray(
            np.frombuffer(ci, dtype=np.uint8).reshape(sh)
        ).save(f"encrypted/encrypted_{st}_{alg}.png")

        with open(bp, "rb") as f:
            sv = f.read()

        if alg == "xor":
            pt = xor_crypt(sv, xk)
        elif alg == "aes-ecb":
            pt = aes_ecb_decrypt(sv, ak)
        else:
            pt = aes_ctr_decrypt(sv, ak, n)

        Image.fromarray(
            np.frombuffer(pt, dtype=np.uint8).reshape(sh)
        ).save(f"recover/recovered_{st}_{alg}.png")

        rev = pt == ob

        ent = calculate_entropy(ci)
        ca = np.frombuffer(ci, dtype=np.uint8).reshape(sh)
        ch = calculate_correlation(ca, "horizontal")
        cv = calculate_correlation(ca, "vertical")

        bl = [cf[i:i + 16] for i in range(0, len(cf), 16)]
        rp = len(bl) - len(set(bl))

        rs.append({
            "изображение": src,
            "метод": alg,
            "энтропия": round(ent, 6),
            "корреляция X": round(ch, 6),
            "корреляция Y": round(cv, 6),
            "обратимость": rev,
            "повтор_блоков": rp,
            "npcr": "",
            "uaci": "",
        })

        plot_histograms(
            {"Оригинал": ob, alg.upper(): ci},
            filename=f"results/histograms_{st}_{alg}.png",
        )

        if src == "gradient.png":
            if alg == "xor":
                k2 = bytearray(xk)
                k2[0] ^= 0x01
                k2 = bytes(k2)
                c2 = xor_crypt(ob, k2)
            elif alg == "aes-ecb":
                k2 = bytearray(ak)
                k2[0] ^= 0x01
                k2 = bytes(k2)
                c2 = aes_ecb_encrypt(ob, k2)[:len(ob)]
            else:
                k2 = bytearray(ak)
                k2[0] ^= 0x01
                k2 = bytes(k2)
                c2, _ = aes_ctr_encrypt(ob, k2, nonce=n)

            npcr, uaci = calculate_npcr_uaci(ci, c2)
            rs[-1]["npcr"] = round(npcr, 2)
            rs[-1]["uaci"] = round(uaci, 2)

    with open("results/data.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=[
            "изображение", "метод", "энтропия", "корреляция X", "корреляция Y",
            "обратимость", "повтор_блоков", "npcr", "uaci",
        ])
        w.writeheader()
        for r in rs:
            w.writerow(r)


if __name__ == "__main__":
    main()