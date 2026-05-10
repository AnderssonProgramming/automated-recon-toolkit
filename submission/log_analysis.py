import re, statistics
from collections import Counter

ATTACK_PATTERNS = re.compile(r"(union.*select|\.\./|<script|cmd=)", re.IGNORECASE)

def analyze():
    ips = Counter()
    statuses = Counter()
    hourly = Counter()
    attacks = []
    
    with open("access.log", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 9: continue
            ip, ts, path, status = parts[0], parts[3][1:], parts[6], parts[8]
            
            ips[ip] += 1
            statuses[status] += 1
            hour = ts.split(":")[1]
            hourly[hour] += 1
            
            if ATTACK_PATTERNS.search(path):
                attacks.append((ip, path))
                
    print("--- ATTACKS FOUND ---")
    for ip, path in attacks[:5]: print(f"{ip} -> {path}")
    
    print("\n--- TOP 5 IPs ---")
    for ip, count in ips.most_common(5): print(f"{ip}: {count}")
    
    print("\n--- 3-SIGMA ANOMALIES ---")
    counts = list(hourly.values())
    if len(counts) >= 2:
        mean, stdev = statistics.mean(counts), statistics.stdev(counts)
        for hr, count in hourly.items():
            if count > mean + 3 * stdev:
                z = (count - mean) / stdev
                print(f"[ANOMALY] Hour {hr} - {count} requests (z={z:.1f}σ)")

if __name__ == "__main__":
    analyze()
