# NetScan 🔍

A lightweight, multithreaded TCP port scanner and banner grabber written in pure Python (no third-party dependencies).

Built as a portfolio project to demonstrate core networking and cybersecurity fundamentals: sockets, concurrency, CLI design, and safe/ethical scanning practices.

## Features

- Fast multithreaded TCP connect scanning
- Custom port ranges or lists (`1-1024`, `22,80,443`, etc.)
- Optional service banner grabbing
- Save results to a file
- Zero external dependencies — uses only the Python standard library

## Installation

```bash
git clone https://github.com/<your-username>/netscan.git
cd netscan
python3 netscan.py --help
```

Requires Python 3.7+.

## Usage

Scan the default range (ports 1–1024) on a target:

```bash
python3 netscan.py scanme.nmap.org
```

Scan specific ports with banner grabbing:

```bash
python3 netscan.py scanme.nmap.org -p 22,80,443 -b
```

Scan a custom range with more threads and save results:

```bash
python3 netscan.py 192.168.1.1 -p 1-65535 -t 200 -o results.txt
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --ports` | Ports or ranges to scan | `1-1024` |
| `-t, --threads` | Number of concurrent threads | `100` |
| `--timeout` | Socket timeout (seconds) | `1.0` |
| `-b, --banner` | Attempt to grab service banners | off |
| `-o, --output` | Save results to a file | none |

## Example Output

```
=======================================================
  NetScan - Target: scanme.nmap.org (45.33.32.156)
  Ports: 22,80,443  |  Threads: 100
  Started: 2026-09-25 14:02:11
=======================================================
[+] Port    22 OPEN   (ssh) -- SSH-2.0-OpenSSH_6.6.1p1
[+] Port    80 OPEN   (http)
-------------------------------------------------------
[*] Scan completed in 1.84 seconds.
[*] 2 open port(s) found.
```

## ⚠️ Legal / Ethical Use

This tool is for **educational purposes and authorized security testing only**. Only scan systems you own or have **explicit written permission** to test. Unauthorized port scanning may violate the Computer Fraud and Abuse Act (U.S.) or equivalent laws elsewhere.

[scanme.nmap.org](http://scanme.nmap.org) is provided by Nmap's creators specifically for testing scanners like this one.

## What I Learned

- How TCP connect scans work at the socket level
- Managing concurrency safely with `threading` and `queue`
- Designing a clean CLI with `argparse`
- Balancing scan speed against reliability (timeouts, thread counts)

## Roadmap Ideas

- [ ] Add UDP scan support
- [ ] Add `-sV` style service/version fingerprinting
- [ ] Export results as JSON/CSV
- [ ] Add a `--stealth` SYN scan mode (requires raw sockets/root)

## License

MIT
