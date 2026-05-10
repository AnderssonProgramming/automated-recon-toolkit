import xml.etree.ElementTree as ET
import subprocess
import json
import argparse

def run_ssh_keyscan(ip):
    try:
        res = subprocess.run(["ssh-keyscan", "-t", "rsa,ecdsa,ed25519", ip], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            if not line.startswith("#"):
                return line.split()[1] # returns key type e.g., ssh-ed25519
    except Exception:
        pass
    return "Unknown/Timeout"

def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    hosts_data = []
    for host in tree.findall("host"):
        addr = host.find("address").get("addr")
        host_dict = {"ip": addr, "open_ports": []}
        
        for port in host.findall(".//port"):
            if port.find("state").get("state") == "open":
                p_id = int(port.get("portid"))
                svc = port.find("service")
                svc_name = svc.get("name") if svc is not None else "unknown"
                svc_ver = svc.get("version") if svc is not None else ""
                
                p_info = {"port": p_id, "service": svc_name, "version": svc_ver}
                if p_id == 22:
                    p_info["ssh_host_key_type"] = run_ssh_keyscan(addr)
                host_dict["open_ports"].append(p_info)
        
        if host_dict["open_ports"]:
            hosts_data.append(host_dict)
    return hosts_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    
    data = parse_nmap(args.input)
    with open(args.output, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Parsed {len(data)} hosts. Saved to {args.output}")
