import pandas as pd
import matplotlib.pyplot as plt
import os

# === 使用者可更換這兩個路徑 ===
BASE_DIR = "output"
CSV1 = "fitness_log_traditional.csv"            # 改成你的第一份 CSV 檔名
CSV2 = "random_sample_results.csv"    # 改成你的第二份 CSV 檔名
LABEL1 = "GA"
LABEL2 = "Random"

# === 產出圖檔路徑 ===
OUTPUT_PNG = os.path.join(BASE_DIR, f"compare_{LABEL1.replace(' ', '_')}_vs_{LABEL2.replace(' ', '_')}.png")

# === 讀取資料 ===
df1 = pd.read_csv(os.path.join(BASE_DIR, CSV1))
df2 = pd.read_csv(os.path.join(BASE_DIR, CSV2))

# === 畫圖 ===
plt.figure(figsize=(8, 5))
plt.plot(df1["generation"], df1["avg_fitness"], label=f"{LABEL1} - Avg", linestyle='-', marker='o')
plt.plot(df1["generation"], df1["max_fitness"], label=f"{LABEL1} - Max", linestyle='--', marker='x')
plt.plot(df2["generation"], df2["avg_fitness"], label=f"{LABEL2} - Avg", linestyle='-', marker='s')
plt.plot(df2["generation"], df2["max_fitness"], label=f"{LABEL2} - Max", linestyle='--', marker='^')

plt.xlabel("Generation")
plt.ylabel("Fitness")
plt.title(f"Comparison: {LABEL1} vs {LABEL2}")
plt.legend(loc='lower right', frameon=True)
plt.grid(True)
plt.tight_layout()
plt.savefig(OUTPUT_PNG)
plt.close()

print(f"[DONE] Saved comparison plot to {OUTPUT_PNG}")
