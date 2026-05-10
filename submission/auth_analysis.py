from collections import defaultdict
import re

AUTH_FAIL = re.compile(r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)")
AUTH_SUCC = re.compile(r"Accepted publickey for (\S+) from (\d+\.\d+\.\d+\.\d+)")

def analyze():
    failed_ips = defaultdict(int)
    targeted_users = set()
    fails, succs = 0, 0
    
    with open("auth.log", "r") as f:
        for line in f:
            if m := AUTH_FAIL.search(line):
                targeted_users.add(m.group(1))
                failed_ips[m.group(2)] += 1
                fails += 1
            elif AUTH_SUCC.search(line):
                succs += 1
                
    print(f"Ratio (Failed/Success): {fails}/{succs} = {fails/max(1,succs):.2f}")
    print("Targeted users:", ", ".join(targeted_users))
    print("IPs > 10 fails:")
    for ip, count in sorted(failed_ips.items(), key=lambda x: x[1], reverse=True):
        if count > 10: print(f"  {ip}: {count} attempts")

if __name__ == "__main__":
    analyze()
