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
ELITE_COUNT = 5
EMA_ALPHA = 0.4
NUM_VULNS = 13
MAIN_ATTACKER = "TargetedAttacker"

random_seed = int(time.time())
#random.seed(random_seed)
random.seed(1748251999) #1748251999 1748335351 1748944989 1748961040 1748945899 1748964033 1748964084 1748964120 1748964154 1748964172
print(f"[INFO] Random Seed: {random_seed}")

# 載入資料
with open("data/attacker_profiles.json") as f:
    attacker_profiles_dict = json.load(f)
    
with open("data/vuln_to_tech.json") as f:
    vuln_to_tech = json.load(f)

with open("data/tech_score_table.json") as f:
    tech_score_table = json.load(f)

# === Early Stopper ===
class EarlyStopper:
    def __init__(self, patience=10, min_delta=0.001):
        self.patience = patience
        self.min_delta = min_delta
        self.counter = 0
        self.best_score = None

    def check(self, current_score):
        if self.best_score is None:
            self.best_score = current_score
            return False
        if current_score - self.best_score >= self.min_delta:
            self.best_score = current_score
            self.counter = 0
        else:
            self.counter += 1
        return self.counter >= self.patience

# === GA 主要方法 ===
def generate_individual():
    return [random.randint(0, 1) for _ in range(NUM_VULNS)]

def generate_population():
    return [generate_individual() for _ in range(POPULATION_SIZE)]

def mutate(individual):
    return [1 - bit if random.random() < MUTATION_RATE else bit for bit in individual]

def crossover(parent1, parent2):
    if random.random() > CROSSOVER_RATE:
        return random.choice([parent1, parent2])
    point = random.randint(1, NUM_VULNS - 1)
    return parent1[:point] + parent2[point:]

def roulette_selection(population, fitness_dict):
    fitnesses = [fitness_dict[tuple(ind)][0] for ind in population]
    total_fitness = sum(fitnesses)
    if total_fitness == 0:
        return random.choice(population)
    pick = random.uniform(0, total_fitness)
    current = 0
    for ind, fit in zip(population, fitnesses):
        current += fit
        if current >= pick:
            return ind

# === EMA 快取 ===
def update_fitness_cache(key, new_fitness, fitness_cache, alpha=EMA_ALPHA):
    if key not in fitness_cache:
        fitness_cache[key] = (new_fitness, 1)
    else:
        prev_fitness, n = fitness_cache[key]
        ema_fitness = alpha * new_fitness + (1 - alpha) * prev_fitness
        fitness_cache[key] = (ema_fitness, n + 1)
    return fitness_cache[key][0]

# === 執行主 GA 流程 ===
log_path = "output/fitness_log_ema.csv"
init_log(log_path)
fitness_cache = {}
early_stopper = EarlyStopper()

population = generate_population()

for generation in range(GENERATIONS):
    print(f"\nGeneration {generation} ----------------------------")
    fitness_list = []

    for individual in population:
        key = tuple(individual)
        result = simulate_attack(individual, attacker_profiles_dict, MAIN_ATTACKER)
        raw_fitness = compute_fitness(result['num_ips'], result['triggered_techniques'], tech_score_table, individual)
        fitness = update_fitness_cache(key, raw_fitness, fitness_cache)
        fitness_list.append((individual, fitness))

    fitness_list.sort(key=lambda x: x[1], reverse=True)
    elites = [ind for ind, _ in fitness_list[:ELITE_COUNT]]

    max_fitness = fitness_list[0][1]
    avg_fitness = sum(f for _, f in fitness_list) / len(fitness_list)
    log_fitness(generation, avg_fitness, max_fitness, log_path)

    enabled_vulns = [i for i, bit in enumerate(elites[0]) if bit == 1]
    print(f"Gen {generation}: Max Fitness = {max_fitness:.4f}, Avg = {avg_fitness:.4f}, Enabled Vulns = {enabled_vulns}")

    if early_stopper.check(max_fitness) or (max_fitness - avg_fitness < 0.015):
        print(f"[EARLY STOP] Triggered at generation {generation} due to no improvement")
        break

    next_generation = elites[:]
    while len(next_generation) < POPULATION_SIZE:
        parent1 = roulette_selection(population, fitness_cache)
        parent2 = roulette_selection(population, fitness_cache)
        child = crossover(parent1, parent2)
        child = mutate(child)
        next_generation.append(child)

    population = next_generation

# === 畫圖 ===
plot_fitness_curve(log_path, "output/fitness_plot_ema.png")
