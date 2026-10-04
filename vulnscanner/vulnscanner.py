"""
Task 2 - Vulnerability Scanner (Mini Project)
ETHICAL USE: scan only systems you own or have written permission to test.
Run:  python vulnerability_scanner.py --demo              (safe, local demo for review)
      python vulnerability_scanner.py 127.0.0.1           (scan a host)
      python vulnerability_scanner.py http://localhost:8000   (also checks web headers)
Features: open-port scan, banner/version grab -> outdated-software check,
weak-configuration checks (missing security headers), report saved to vuln_report.txt.
"""
import argparse, re, socket, sys, threading, http.server, datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from urllib.request import Request, urlopen

PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
         143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
         8000: "HTTP-alt", 8080: "HTTP-proxy"}
RISKY = {21: "FTP is unencrypted", 23: "Telnet is unencrypted - use SSH", 445: "SMB exposure is risky",
         3389: "RDP exposed - brute-force target", 3306: "Database port exposed"}
# minimal known-outdated list: (regex on banner, minimum safe version tuple, advice)
OUTDATED = [(r"OpenSSH[_ ](\d+)\.(\d+)", (8, 0), "OpenSSH"),
            (r"Apache/(\d+)\.(\d+)", (2, 4), "Apache"),
            (r"nginx/(\d+)\.(\d+)", (1, 20), "nginx"),
            (r"vsFTPd (\d+)\.(\d+)", (3, 0), "vsFTPd"),
            (r"Python/(\d+)\.(\d+)", (3, 8), "Python")]
HEADERS = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
           "Strict-Transport-Security"]

def scan_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.6) as s:
            s.settimeout(0.8)
            try:
                if port in (80, 8000, 8080): s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode(errors="ignore").strip()
            except Exception: banner = ""
            return port, banner
    except Exception:
        return None

def check_banner(banner):
    found = []
    for pat, minv, name in OUTDATED:
        m = re.search(pat, banner)
        if m and (int(m.group(1)), int(m.group(2))) < minv:
            found.append(f"Outdated {name} {m.group(1)}.{m.group(2)} (upgrade to >= {'.'.join(map(str, minv))})")
    return found

def check_headers(url):
    issues = []
    try:
        with urlopen(Request(url, method="GET"), timeout=3) as r:
            h = {k.lower() for k in r.headers.keys()}
            server = r.headers.get("Server", "")
            issues += [f"Missing security header: {x}" for x in HEADERS if x.lower() not in h]
            if server: issues.append(f"Server header discloses software: {server}")
            issues += check_banner(server)
    except Exception as e:
        issues.append(f"Web check failed: {e}")
    return issues

def scan(target):
    url = target if target.startswith("http") else None
    host = urlparse(target).hostname if url else target
    findings, openp = [], []
    with ThreadPoolExecutor(30) as ex:
        for r in ex.map(lambda p: scan_port(host, p), PORTS):
            if r: openp.append(r)
    for port, banner in sorted(openp):
        line = f"[OPEN] {port}/{PORTS[port]}" + (f"  banner: {banner.splitlines()[0][:60]}" if banner else "")
        findings.append(line)
        if port in RISKY: findings.append(f"   [WEAK CONFIG] {RISKY[port]}")
        findings += [f"   [OUTDATED] {x}" for x in check_banner(banner)]
    if url: findings += [f"[WEB] {x}" for x in check_headers(url)]
    elif any(p in (80, 8000, 8080) for p, _ in openp):
        p = next(p for p, _ in openp if p in (80, 8000, 8080))
        findings += [f"[WEB] {x}" for x in check_headers(f"http://{host}:{p}")]
    return host, findings

def write_report(host, findings):
    lines = ["VULNERABILITY REPORT", f"Target: {host}", f"Date: {datetime.datetime.now():%Y-%m-%d %H:%M}",
             "-" * 50] + (findings or ["No open ports from the scanned list."]) + \
            ["-" * 50, f"Total findings: {len(findings)}"]
    text = "\n".join(lines); print(text)
    open("vuln_report.txt", "w").write(text); print("\nSaved: vuln_report.txt")

def demo():
    class H(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(("127.0.0.1", 8000), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("Demo: started a local test web server on 127.0.0.1:8000\n")
    write_report(*scan("127.0.0.1")); srv.shutdown()

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("target", nargs="?", default="127.0.0.1")
    ap.add_argument("--demo", action="store_true"); a = ap.parse_args()
    demo() if a.demo else write_report(*scan(a.target))