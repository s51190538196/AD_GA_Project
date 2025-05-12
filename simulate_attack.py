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
    num_ips = 0
    enabled_vulns = set(i for i, v in enumerate(individual) if v == 1)

    # 由現在開啟的漏潛檢索可能起作的技術
    vuln_triggered_techs = set()
    for v in enabled_vulns:
        vuln_triggered_techs.update(vuln_to_tech.get(str(v), []))

    
    # 分離目標與噪音攻擊者
    all_main_attackers = {k: v for k, v in attacker_profiles.items() if not v.get("noise", False) and k.startswith(main_attacker_prefix)}
    noise_attackers = {k: v for k, v in attacker_profiles.items() if v.get("noise", False)}

    # === 每次攻擊採用一種目標攻擊者類型 ===
    if not all_main_attackers:
        raise ValueError("No main attackers found with prefix: " + main_attacker_prefix)

    # 目標攻擊者類型已不是全部主攻者，而是階段性地隊列一個
    if len(all_main_attackers) != 1:
        raise ValueError("Expected exactly one main attacker with prefix '" + main_attacker_prefix + "', but found " + str(len(all_main_attackers)))
    selected_main_attacker = list(all_main_attackers.values())[0]

    # 計算這組漏洞會誘發哪些技術
    preferred_techs = set(selected_main_attacker.get("tech_preference", {}).keys())
    matched_techs = vuln_triggered_techs & preferred_techs
    num_matched = len(matched_techs)

    # 根據命中數映射到攻擊者總數（自訂區間）
    if num_matched == 0:
        estimated_total = random.randint(5, 10)
    elif num_matched <= 2:
        estimated_total = random.randint(20, 35)
    elif num_matched <= 4:
        estimated_total = random.randint(50, 65)
    else:
        estimated_total = random.randint(85, 105)

    # 分配目標與噪音攻擊者數量（7:3）
    main_count = int(estimated_total * 0.3)
    noise_count = estimated_total - main_count

    #print(f"[DEBUG] Matched techniques: {num_matched}, Total attackers: {estimated_total} → Main: {main_count}, Noise: {noise_count}")

    # === 主攻擊者 ===
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
                """
                print(f"[DEBUG] MAIN triggered: {tech} ← from vuln {sorted(actual_sources)} (among possible: {sorted(related_vulns)})")

            else:
                print(f"[DEBUG] MAIN not triggered: {tech} ← from vuln {sorted(related_vulns & enabled_vulns)} (prob={prob:.2f})")
                """
        num_ips += 1

    # === 噪音攻擊者（與主流邏輯相同）===
    noise_keys = list(noise_attackers.keys())
    for _ in range(noise_count):
        attacker = random.choice(list(noise_attackers.values()))
        tech_preference = attacker.get("tech_preference", {})
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
                """
                print(f"[DEBUG] Noise triggered: {tech} ← from vuln {sorted(actual_sources)} (among possible: {sorted(related_vulns)})")

            else:
                print(f"[DEBUG] Noise not triggered: {tech} ← from vuln {sorted(related_vulns & enabled_vulns)} (prob={prob:.2f})")
                """
        num_ips += 1


    return {
        'num_ips': num_ips,
        'triggered_techniques': list(triggered_techniques)
    }
