import json
import random
import time
from compute_fitness import compute_fitness
from simulate_attack import simulate_attack
from fitness_logger import init_log, log_fitness
from plot_fitness import plot_fitness_curve

# 參數設定
POPULATION_SIZE = 15
GENERATIONS = 100
MUTATION_RATE = 0.1
CROSSOVER_RATE = 0.8
#TOURNAMENT_SIZE = 3
ELITE_COUNT = 5
EMA_ALPHA = 0.4
NUM_VULNS = 13
MAIN_ATTACKER = "TargetedAttacker2"


# 取一個指定亂數種子（或根據時間產生，但你知道它是誰）
random_seed = int(time.time())  # 也可以手動設 random_seed = 1747034175, 1747052101, 1747052182, 1747052272, 1747052620, 1747059873(best)
#random_seed = 1747059873
random.seed(random_seed)

print(f"[INFO] Random Seed: {random_seed}")

# 載入資料
with open("data/attacker_profiles.json") as f:
    attacker_profiles_dict = json.load(f)

with open("data/vuln_to_tech.json") as f:
    vuln_to_tech = json.load(f)

with open("data/tech_score_table.json") as f:
    tech_score_table = json.load(f)

# early_stop_check: 提供 early stopping 功能
class EarlyStopper:
    def __init__(self, patience=10, min_delta=0.001):
        self.patience = patience        # 容忍幾代沒進步
        self.min_delta = min_delta      # 最小進步量
        self.counter = 0                # 已連續幾代沒進步
        self.best_score = None          # 目前為止最高分

    def check(self, current_score):
        if self.best_score is None:
            self.best_score = current_score
            return False

        if current_score - self.best_score >= self.min_delta:
            self.best_score = current_score
            self.counter = 0  # 有進步就重設計數器
        else:
            self.counter += 1

        return self.counter >= self.patience  # 達到容忍次數 → 停止


# 初始化族群
def generate_individual():
    return [random.randint(0, 1) for _ in range(NUM_VULNS)]

def generate_population():
    return [generate_individual() for _ in range(POPULATION_SIZE)]

# 競賽選擇
"""
def roulette_selection(population, fitness_cache):
    selected = random.sample(population, TOURNAMENT_SIZE)
    selected.sort(key=lambda ind: fitness_cache.get(tuple(ind), (0,))[0], reverse=True)
    return selected[0]
"""

def roulette_selection(population, fitness_cache):
    fitnesses = [fitness_cache[tuple(ind)][0] for ind in population]
    total_fitness = sum(fitnesses)
    if total_fitness == 0:
        return random.choice(population)  # 避免除以 0
    pick = random.uniform(0, total_fitness)
    current = 0
    for ind, fit in zip(population, fitnesses):
        current += fit
        if current >= pick:
            return ind

# 根據 elites 統計每一位的 p_i 機率
def compute_bias_map(elites):
    bias_map = []
    for i in range(NUM_VULNS):
        count = sum(ind[i] for ind in elites)
        p_i = count / len(elites)
        bias_map.append(p_i)
    return bias_map

# Bias-guided 突變（基於 p_i）

def mutate(individual, bias):
    return [
        bit if random.random() > (MUTATION_RATE * (1 - bias[i]))
        else 1 - bit
        for i, bit in enumerate(individual)
    ]

"""
def mutate(individual):
    return [
        1 - bit if random.random() < MUTATION_RATE else bit
        for bit in individual
    ]
"""

# 交配（單點）
def crossover(parent1, parent2):
    if random.random() > CROSSOVER_RATE:
        return random.choice([parent1, parent2])
    point = random.randint(1, NUM_VULNS - 1)
    return parent1[:point] + parent2[point:]



log_path = "output/fitness_log.csv"
init_log(log_path)
bias_map = [0.5 for _ in range(NUM_VULNS)]
fitness_cache = {}

# 初始化 early stopper
early_stopper = EarlyStopper(patience=10, min_delta=0.001)

population = generate_population()

for generation in range(GENERATIONS):
    print(f"\n Generation {generation} ----------------------------")
    fitness_list = []
    for individual in population:
        key = tuple(individual)
        if key not in fitness_cache:
            result = simulate_attack(individual, attacker_profiles_dict, MAIN_ATTACKER)
            fitness = compute_fitness(result['num_ips'], result['triggered_techniques'], tech_score_table, individual)
            fitness_cache[key] = (fitness, 1)
        else:
            fitness, count = fitness_cache[key]
            result = simulate_attack(individual, attacker_profiles_dict, MAIN_ATTACKER)
            new_fitness = compute_fitness(result['num_ips'], result['triggered_techniques'], tech_score_table, individual)
            fitness = EMA_ALPHA * new_fitness + (1 - EMA_ALPHA) * fitness
            fitness_cache[key] = (fitness, count + 1)
        fitness_list.append((individual, fitness))

    fitness_list.sort(key=lambda x: x[1], reverse=True)
    elites = [ind for ind, _ in fitness_list[:ELITE_COUNT]]
    max_fitness = fitness_list[0][1]
    avg_fitness = sum(f for _, f in fitness_list) / len(fitness_list)

    log_fitness(generation, avg_fitness, max_fitness, log_path)
    enabled_vulns = [i for i, bit in enumerate(elites[0]) if bit == 1]
    print(f"Gen {generation}: Max Fitness = {max_fitness:.4f}, Avg = {avg_fitness:.4f}, Enabled Vulns = {enabled_vulns}")
    print(f"Gap: {max_fitness - avg_fitness:.4f}")


    #如果進步很小就停止演化
    
    if ((early_stopper.check(max_fitness)) or (max_fitness - avg_fitness < 0.015)):
        print(f"[EARLY STOP] Triggered at generation {generation} due to no improvement")
        break
    
    #開始進行下一代演化
    bias_map = compute_bias_map(elites)

    next_generation = elites[:]
    while len(next_generation) < POPULATION_SIZE:
        parent1 = roulette_selection(population, fitness_cache)
        parent2 = roulette_selection(population, fitness_cache)
        child = crossover(parent1, parent2)
        #child = mutate(child)
        child = mutate(child, bias_map)
        next_generation.append(child)

    population = next_generation

print("\nFinal Generation Population:")
for i, individual in enumerate(population):
    enabled_vulns = [i for i, bit in enumerate(individual) if bit == 1]
    print(f"Individual {i + 1}: {individual} → Enabled vulns: {enabled_vulns}")

plot_fitness_curve(log_path, "output/fitness_plot.png")
