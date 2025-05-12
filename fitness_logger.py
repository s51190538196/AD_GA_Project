import csv
import os


def init_log(file_path):
    header = ["generation", "avg_fitness", "max_fitness"]
    with open(file_path, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)


def log_fitness(generation, avg_fitness, max_fitness, file_path="fitness_log.csv"):
    with open(file_path, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([generation, avg_fitness, max_fitness])
