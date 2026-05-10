import argparse, subprocess, os, json, datetime, logging

def run_cmd(cmd):
    logging.info(f"Running: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        logging.info(f"Success. Exit code: {res.returncode}")
        return res.stdout
    except Exception as e:
        logging.error(f"Failed: {e}")
        return ""

def generate_report(data, out_dir):
    with open(f"{out_dir}/report.md", "w") as f:
        f.write("# Recon Report\n\n")
        f.write("## Summary\n```json\n" + json.dumps(data, indent=2) + "\n```\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--mode", choices=["domain", "ip"])
    parser.add_argument("--output")
    args = parser.parse_args()

    mode = args.mode if args.mode else ("ip" if args.target.replace('.','').isdigit() else "domain")
    out_dir = args.output or f"./recon_{args.target}_{datetime.datetime.now():%Y%m%d}"
    os.makedirs(out_dir, exist_ok=True)
    
    logging.basicConfig(filename=f"{out_dir}/audit.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    results = {"target": args.target, "mode": mode}
    print(f"Starting {mode} recon on {args.target}...")

    if mode == "domain":
        results["whois"] = run_cmd(["whois", args.target])[:200] # Trimmed for briefness
        results["dig"] = run_cmd(["dig", args.target, "ANY"])
        results["headers"] = run_cmd(["curl", "-I", "-s", f"https://{args.target}"])
    else:
        results["nmap"] = run_cmd(["nmap", "-sV", "--top-ports", "100", args.target])
        results["dig_reverse"] = run_cmd(["dig", "-x", args.target])
        results["whois"] = run_cmd(["whois", args.target])[:200]

    with open(f"{out_dir}/results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    generate_report(results, out_dir)
    print(f"Done! Check {out_dir}/")
