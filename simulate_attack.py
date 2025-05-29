import random
import json
from pathlib import Path

# 載入 vuln_to_tech 並反推 TECH_TO_VULN
with open(Path(__file__).parent / "data" / "vuln_to_tech.json", "r") as f:
    vuln_to_tech = json.load(f)

TECH_TO_VULN = {}
for vuln_id, techs in vuln_to_tech.items():
    for tech in techs:
        TECH_TO_VULN.setdefault(tech, set()).add(int(vuln_id))

def simulate_attack(individual, attacker_profiles, main_attacker_prefix="A"):
    triggered_techniques = set()
    triggered_by_vuln = {}  # 新增：記錄技術來源漏洞
    num_ips = 0
    enabled_vulns = set(i for i, v in enumerate(individual) if v == 1)

    # 由現在開啟的漏洞檢索可能啟動的技術
    vuln_triggered_techs = set()
    for v in enabled_vulns:
        vuln_triggered_techs.update(vuln_to_tech.get(str(v), []))

    # 分離目標與噪音攻擊者
    all_main_attackers = {k: v for k, v in attacker_profiles.items() if not v.get("noise", False) and k.startswith(main_attacker_prefix)}
    noise_attackers = {k: v for k, v in attacker_profiles.items() if v.get("noise", False)}

    if not all_main_attackers:
        raise ValueError("No main attackers found with prefix: " + main_attacker_prefix)

    if len(all_main_attackers) != 1:
        raise ValueError("Expected exactly one main attacker with prefix '" + main_attacker_prefix + "', but found " + str(len(all_main_attackers)))

    selected_main_attacker = list(all_main_attackers.values())[0]
    preferred_techs = set(selected_main_attacker.get("tech_preference", {}).keys())
    matched_techs = vuln_triggered_techs & preferred_techs
    num_matched = len(matched_techs)

    if num_matched == 0:
        estimated_total = random.randint(5, 10)
    elif num_matched <= 2:
        estimated_total = random.randint(20, 35)
    elif num_matched <= 4:
        estimated_total = random.randint(50, 65)
    else:
        estimated_total = random.randint(85, 105)

    main_count = int(estimated_total * 0.4)
    noise_count = estimated_total - main_count

    # 主攻擊者
    for _ in range(main_count):
        tech_preference = selected_main_attacker.get("tech_preference", {})
        for tech, pref in tech_preference.items():
            if tech not in vuln_triggered_techs:
                continue
            related_vulns = TECH_TO_VULN.get(tech, set())
            if not (related_vulns & enabled_vulns):
                continue
            prob = pref
            if random.random() < prob:
                triggered_techniques.add(tech)
                actual_sources = related_vulns & enabled_vulns
                triggered_by_vuln.setdefault(tech, set()).update(actual_sources)
        num_ips += 1

    # 噪音攻擊者（限制每一個最多觸發 1~2 條技術）
    noise_keys = list(noise_attackers.keys())
    for _ in range(noise_count):
        attacker = random.choice(list(noise_attackers.values()))
        tech_preference = attacker.get("tech_preference", {})

        # Step 1: 先經標準條件與機率達成的技術清單
        candidate_techs = []
        for tech, pref in tech_preference.items():
            related_vulns = TECH_TO_VULN.get(tech, set())
            if not (related_vulns & enabled_vulns):
                continue
            if random.random() < pref:
                candidate_techs.append(tech)

        # Step 2: 抽最多 1~2 條技術來觸發
        chosen_techs = random.sample(candidate_techs, min(len(candidate_techs), 1))

        for tech in chosen_techs:
            triggered_techniques.add(tech)
            actual_sources = TECH_TO_VULN.get(tech, set()) & enabled_vulns
            triggered_by_vuln.setdefault(tech, set()).update(actual_sources)

        num_ips += 1

    return {
        'num_ips': num_ips,
        'triggered_techniques': list(triggered_techniques),
        'triggered_by_vuln': {k: list(v) for k, v in triggered_by_vuln.items()}
    }
