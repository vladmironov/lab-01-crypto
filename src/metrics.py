import numpy as np
import matplotlib.pyplot as plt

def bytes_to_array(data: bytes):
    return np.frombuffer(data, dtype=np.uint8)

def calculate_entropy(data: bytes) -> float:
    arr = bytes_to_array(data)
    counts = np.bincount(arr, minlength=256)
    probs = counts / len(arr)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))

def calculate_correlation(img_array: np.ndarray, direction='horizontal'):
    if direction == 'horizontal':
        x = img_array[:, :-1, :].flatten()
        y = img_array[:, 1:, :].flatten()
    elif direction == 'vertical':
        x = img_array[:-1, :, :].flatten()
        y = img_array[1:, :, :].flatten()
    else:
        raise ValueError("Направление только 'horizontal' или 'vertical'")

    if np.std(x) == 0 or np.std(y) == 0:
        return 0.0
    return float(np.corrcoef(x, y)[0, 1])

def plot_histograms(data_dict: dict, filename="results/histograms.png"):
    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    axes = axes.ravel()
    for ax, (title, data) in zip(axes, data_dict.items()):
        arr = bytes_to_array(data)
        ax.hist(arr, bins=256, range=(0, 256), color='steelblue', alpha=0.8)
        ax.set_title(title)
        ax.set_xlim(0, 255)
        ax.set_xlabel('Значение байта')
        ax.set_ylabel('Частота')
    plt.tight_layout()
    plt.savefig(filename, dpi=150)
    plt.close()

def calculate_npcr_uaci(c1: bytes, c2: bytes):
    a = bytes_to_array(c1).astype(np.int16)
    b = bytes_to_array(c2).astype(np.int16)
    n = len(a)
    npcr = (np.sum(a != b) / n) * 100.0
    uaci = (np.sum(np.abs(a - b)) / (255.0 * n)) * 100.0
    return float(npcr), float(uaci)