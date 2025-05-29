import random
import time
import json
import os
import csv
import matplotlib.pyplot as plt
import pandas as pd
from compute_fitness import compute_fitness
from simulate_attack import simulate_attack

NUM_VULNS = 15
POPULATION_SIZE = 10
GENERATIONS = 26
SAMPLE_SIZE = 300
MAIN_ATTACKER = "TargetedAttacker2"
OUTPUT_DIR = "output"
OUTPUT_CSV = f"{OUTPUT_DIR}/random_sample_results.csv"

# 載入資料
with open("data/attacker_profiles.json") as f:
    attacker_profiles = json.load(f)
with open("data/tech_score_table.json") as f:
    tech_score_table = json.load(f)

# 確保 output 資料夾存在
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 產生樣本
def generate_individual():
    max_enabled = random.randint(1, 13)  # 每次隨機開啟 2 到 7 個漏洞
    indices = random.sample(range(NUM_VULNS), max_enabled)
    individual = [0] * NUM_VULNS
    for idx in indices:
        individual[idx] = 1
    return individual

random_seed = int(time.time())
#random.seed(random_seed)
random.seed(1748335351) #1748267247

results = []
for generation in range(GENERATIONS):
    for _ in range(POPULATION_SIZE):
        ind = generate_individual()
        result = simulate_attack(ind, attacker_profiles, MAIN_ATTACKER)
        fitness = compute_fitness(result['num_ips'], result['triggered_techniques'], tech_score_table, ind)
        results.append({
            "generation": generation,
            "fitness": fitness,
            "num_ips": result['num_ips'],
            "triggered_techniques": len(result['triggered_techniques']),
            "num_vulns": sum(ind)
        })
        # ✅ 如果是最後一代就印出該個體的基因（哪幾個漏洞被打開）
        if generation == GENERATIONS - 1:
            enabled = [idx for idx, bit in enumerate(ind) if bit == 1]
            print(f"[GEN {generation}] Individual: {ind} → Enabled vulns: {enabled}")

# 儲存為 CSV
with open(OUTPUT_CSV, "w", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=["generation", "fitness", "num_ips", "triggered_techniques", "num_vulns"]
)
    writer.writeheader()
    writer.writerows(results)

print(f"[DONE] Saved {SAMPLE_SIZE} samples to {OUTPUT_CSV}")
