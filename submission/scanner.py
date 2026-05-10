import asyncio
import argparse
import time
import json

async def scan_port(host, port, timeout):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None

async def scan_host_limited(host, ports, max_concurrent, timeout):
    semaphore = asyncio.Semaphore(max_concurrent)
    async def limited_scan(port):
        async with semaphore:
            return await scan_port(host, port, timeout)
    results = await asyncio.gather(*[limited_scan(p) for p in ports])
    return sorted(p for p in results if p is not None)

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1024")
    parser.add_argument("--rate", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("-o", "--output", default="scan_results.json")
    args = parser.parse_args()

    ports_to_scan = parse_ports(args.ports)
    start_time = time.perf_counter()
    
    open_ports = asyncio.run(scan_host_limited(args.target, ports_to_scan, args.rate, args.timeout))
    
    elapsed = time.perf_counter() - start_time
    print(f"Open ports on {args.target}: {open_ports} (Time: {elapsed:.2f}s)")
    
    result = {
        "target": args.target, "scan_time_seconds": round(elapsed, 2),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "open_ports": open_ports
    }
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
