import matplotlib.pyplot as plt
import csv

def plot_fitness_curve(csv_path, output_path="fitness_plot.png"):
    generations = []
    avg_fitness = []
    max_fitness = []

    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            generations.append(int(row["generation"]))
            avg_fitness.append(float(row["avg_fitness"]))
            max_fitness.append(float(row["max_fitness"]))

    plt.figure()
    plt.plot(generations, avg_fitness, label="Average Fitness", marker='o')
    plt.plot(generations, max_fitness, label="Max Fitness", marker='x')
    plt.xlabel("Generation")
    plt.ylabel("Fitness")
    plt.title("Fitness Convergence Curve")
    plt.xticks(ticks=generations[::2])
    plt.legend()
    plt.grid(True)
    plt.savefig(output_path)
    plt.close()