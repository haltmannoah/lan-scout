import argparse
import csv
import ipaddress
import json
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_PORTS = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    135: "MSRPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-Alt",
}

# gets flipped to True the first time ping fails because the binary is
# missing, so we don't print the same warning for every single host
_no_ping_warning_shown = False


def ping_host(ip: str, timeout: int = 800) -> bool:
    """
    Ping a host once.
    timeout is milliseconds on Windows, seconds-ish behavior on Linux/macOS.
    """
    global _no_ping_warning_shown
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        if not _no_ping_warning_shown:
            print("Can't find the ping command on this system, skipping ping checks.")
            _no_ping_warning_shown = True
        return False

    return result.returncode == 0


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def parse_ports(port_string):
    # turns "22,80,443" into {22: "SSH", 80: "HTTP", 443: "HTTPS"}
    # anything not in COMMON_PORTS just gets labeled "Custom"
    ports = {}
    for chunk in port_string.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        port_num = int(chunk)
        ports[port_num] = COMMON_PORTS.get(port_num, "Custom")
    return ports


def scan_host(ip: str, ports_to_check=None) -> dict | None:
    if not ping_host(ip):
        return None

    if ports_to_check is None:
        ports_to_check = COMMON_PORTS

    hostname = reverse_dns(ip)
    open_ports = []

    for port, service in ports_to_check.items():
        if check_port(ip, port):
            open_ports.append(f"{port}/{service}")

    return {
        "ip": ip,
        "hostname": hostname,
        "ports": open_ports
    }


def save_results(results, filename):
    if filename.lower().endswith(".csv"):
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "hostname", "ports"])
            for r in results:
                writer.writerow([r["ip"], r["hostname"], "; ".join(r["ports"])])
    else:
        # anything that isn't .csv just gets saved as json
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)

    print(f"Saved {len(results)} results to {filename}")


def scan_network(cidr: str, threads: int = 64, ports_to_check=None):
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    print(f"\nScanning {cidr}...")
    print(f"Hosts to check: {len(hosts)}\n")

    results = []
    checked = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {
            executor.submit(scan_host, ip, ports_to_check): ip
            for ip in hosts
        }

        for future in as_completed(future_to_ip):
            result = future.result()
            checked += 1
            print(f"\rChecked {checked}/{len(hosts)} hosts", end="", flush=True)
            if result:
                results.append(result)

    print()  # move past the progress line

    # sort by actual ip value so .2 comes before .10 instead of string order
    results.sort(key=lambda r: ipaddress.ip_address(r["ip"]))

    for result in results:
        ports = ", ".join(result["ports"]) if result["ports"] else "No common ports open"
        print(f"[+] {result['ip']:<15} {result['hostname']:<35} {ports}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="LAN Scout - discover live devices on your local network"
    )

    parser.add_argument(
        "cidr",
        help="Network range, example: 192.168.1.0/24"
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=64,
        help="Number of threads to use. Default: 64"
    )

    parser.add_argument(
        "-p",
        "--ports",
        help="Comma separated ports to check instead of the defaults, example: 22,80,443"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save results to a file, .json or .csv depending on the extension"
    )

    args = parser.parse_args()

    ports_to_check = None
    if args.ports:
        ports_to_check = parse_ports(args.ports)

    try:
        results = scan_network(args.cidr, args.threads, ports_to_check)
    except ValueError:
        print("Invalid CIDR range. Example: 192.168.1.0/24")
        return

    print("\nScan complete.")
    print(f"Live hosts found: {len(results)}")

    if args.output:
        save_results(results, args.output)


if __name__ == "__main__":
    main()