#!/usr/bin/env python3
"""
NetScan - A lightweight multithreaded TCP port scanner and banner grabber.

Author: <your name here>
License: MIT

DISCLAIMER:
This tool is intended for educational purposes and authorized security
testing only. Only scan hosts and networks you own or have explicit
written permission to test. Unauthorized scanning of systems may violate
the Computer Fraud and Abuse Act (US) or equivalent laws in your
jurisdiction.
"""

import argparse
import socket
import sys
import threading
import queue
import time
from datetime import datetime

# Thread-safe queue and results list
print_lock = threading.Lock()
results = []


def parse_ports(port_string):
    """Parse a port string like '22,80,443' or '1-1024' into a list of ints."""
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def grab_banner(sock):
    """Attempt to read a service banner from an open socket."""
    try:
        sock.settimeout(1.5)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else "No banner"
    except (socket.timeout, ConnectionResetError, OSError):
        return "No banner"


def scan_port(target, port, timeout, grab_banners):
    """Attempt a TCP connection to a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = "unknown"
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    pass

                banner = grab_banner(sock) if grab_banners else None

                with print_lock:
                    line = f"[+] Port {port:>5} OPEN   ({service})"
                    if banner:
                        line += f" -- {banner}"
                    print(line)
                    results.append({"port": port, "service": service, "banner": banner})
    except socket.gaierror:
        with print_lock:
            print(f"[!] Hostname could not be resolved: {target}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)


def worker(target, timeout, grab_banners, q):
    while not q.empty():
        port = q.get()
        scan_port(target, port, timeout, grab_banners)
        q.task_done()


def run_scan(target, ports, threads, timeout, grab_banners):
    q = queue.Queue()
    for port in ports:
        q.put(port)

    thread_list = []
    for _ in range(min(threads, len(ports)) or 1):
        t = threading.Thread(target=worker, args=(target, timeout, grab_banners, q))
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()


def main():
    parser = argparse.ArgumentParser(
        description="NetScan - A simple multithreaded TCP port scanner.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan, e.g. '22,80,443' or '1-1024'"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of concurrent threads"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds"
    )
    parser.add_argument(
        "-b", "--banner", action="store_true",
        help="Attempt to grab service banners from open ports"
    )
    parser.add_argument(
        "-o", "--output", help="Save results to a file (e.g. results.txt)"
    )

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {args.target}")
        sys.exit(1)

    ports = parse_ports(args.ports)

    print("=" * 55)
    print(f"  NetScan - Target: {args.target} ({target_ip})")
    print(f"  Ports: {args.ports}  |  Threads: {args.threads}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    start = time.time()
    try:
        run_scan(target_ip, ports, args.threads, args.timeout, args.banner)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)

    elapsed = time.time() - start
    print("-" * 55)
    print(f"[*] Scan completed in {elapsed:.2f} seconds.")
    print(f"[*] {len(results)} open port(s) found.")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"NetScan results for {args.target} ({target_ip})\n")
            f.write(f"Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for r in sorted(results, key=lambda x: x["port"]):
                line = f"Port {r['port']} OPEN ({r['service']})"
                if r.get("banner"):
                    line += f" -- {r['banner']}"
                f.write(line + "\n")
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
