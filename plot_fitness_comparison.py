import pandas as pd
import matplotlib.pyplot as plt

# 讀取最新上傳的資料
fitness_df = pd.read_csv("output/fitness_log.csv")
random_df = pd.read_csv("output/random_sample_results.csv")

# 計算 Random 每代的平均與最大 fitness
random_stats = random_df.groupby("generation")["fitness"].agg(["mean", "max"]).reset_index()

# 繪製 GA vs Random 收斂走勢圖
plt.figure(figsize=(8, 5))
plt.plot(fitness_df["generation"], fitness_df["max_fitness"], label="Max Fitness (GA)", marker='x', color='blue')
plt.plot(fitness_df["generation"], fitness_df["avg_fitness"], label="Average Fitness (GA)", marker='o', color='green')
plt.plot(random_stats["generation"], random_stats["max"], label="Max Fitness (Random)", marker='x', linestyle='--', color='red')
plt.plot(random_stats["generation"], random_stats["mean"], label="Average Fitness (Random)", marker='o', linestyle='--', color='orange')


plt.xlabel("Generation")
plt.ylabel("Fitness")
plt.title("GA vs. Random Sampling (New Data)")
plt.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), frameon=True)
plt.grid(True)
max_gen = int(max(fitness_df["generation"].max(), random_stats["generation"].max())) + 1
plt.xticks(ticks=range(max_gen))

plt.tight_layout()

output_path = "output/fitness_convergence_ga_vs_random_latest.png"
plt.savefig(output_path)
plt.close()

print(f"Saved plot to: {output_path}")
