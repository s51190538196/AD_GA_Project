import math
def compute_fitness(num_ips, triggered_techniques, tech_score_table, individual,
                    w1=0.2, w2=0.5, w3=0.3):
    MAX_IPS = 105
    MAX_DEPTH_SCORE = sum((v ** 2 for v in tech_score_table.values()))

    raw_depth_score = sum((tech_score_table.get(t, 0) ** 2 for t in triggered_techniques))

    num_vulns = sum(individual)
    vuln_ratio = num_vulns / len(individual)

    scale = 15   # 可以根據實驗調成10~20
    center = 4 / len(individual)  # 期望最佳開啟數（這裡是 4 個漏洞）

    vuln_penalty = 1 / (1 + math.exp(-scale * (vuln_ratio - center)))


    # --- 邊際遞減收益：log 處理 ---
    depth_score = math.log(1 + raw_depth_score)
    normalized_depth = depth_score / math.log(1 + MAX_DEPTH_SCORE)
    # --- IP 數也做邊際遞減收益 ---
    normalized_ips = math.log(1 + num_ips) / math.log(1 + MAX_IPS)
    

    fitness = (
        w1 * normalized_ips +
        w2 * normalized_depth 
       - w3 * vuln_penalty
    )

    return fitness
