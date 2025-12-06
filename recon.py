import argparse
import socket
import ssl
import json
import csv
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time
import http.client
import base64
import tempfile
import os
import sys

# --------------------------------------
# ARGUMENT PARSING
# --------------------------------------
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", required=True)
    parser.add_argument("--ports", required=True)
    parser.add_argument("--http", action="store_true")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--output", required=True)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()

# --------------------------------------
# HELPERS
# --------------------------------------
def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            a, b = map(int, part.split("-"))
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def load_targets(filename):
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]

def http_get(host, port, use_https=False, timeout=5):
    try:
        if use_https:
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout,
                context=ssl._create_unverified_context()
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("GET", "/")
        resp = conn.getresponse()

        status = resp.status
        server = resp.getheader("Server", "")
        body = resp.read(8000).decode("utf-8", errors="ignore")
        conn.close()

        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            title = m.group(1)[:200].strip()

        return {"status_code": status, "server_header": server, "title": title}
    except:
        return None

# --------------------------------------
# GET TLS INFO
# --------------------------------------
def get_tls_info(host, port, timeout=5):
    try:
        context = ssl._create_unverified_context()

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:

                cert_dict = ssock.getpeercert()
                if cert_dict:
                    cn = "unknown"
                    subject = cert_dict.get("subject", [])
                    for item in subject:
                        for (k, v) in item:
                            if k.lower() == "commonname":
                                cn = v
                                break
                        if cn != "unknown":
                            break

                    not_after = cert_dict.get("notAfter", "")
                    return {"subject_cn": cn, "notAfter": not_after}

                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return None

                try:
                    pem = ssl.DER_cert_to_PEM_cert(der)
                except Exception:
                    pem = (
                        "-----BEGIN CERTIFICATE-----\n" +
                        base64.encodebytes(der).decode("ascii") +
                        "-----END CERTIFICATE-----\n"
                    )

                tmp = None
                try:
                    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
                    tmp.write(pem.encode("ascii"))
                    tmp.flush()
                    tmp.close()

                    decoded = None
                    try:
                        decoded = ssl._ssl._test_decode_cert(tmp.name)
                    except Exception:
                        if hasattr(ssl, "_test_decode_cert"):
                            decoded = ssl._test_decode_cert(tmp.name)
                        else:
                            raise

                    if decoded:
                        cn = "unknown"
                        subj = decoded.get("subject", [])
                        for item in subj:
                            for (k, v) in item:
                                if k.lower() == "commonName".lower() or k.lower() == "commonname":
                                    cn = v
                                    break
                            if cn != "unknown":
                                break

                        not_after = decoded.get("notAfter", "")
                        return {"subject_cn": cn, "notAfter": not_after}
                finally:
                    if tmp:
                        try:
                            os.unlink(tmp.name)
                        except Exception:
                            pass

                return None

    except Exception as exc:
        print(f"[tls debug] host={host} port={port} err={exc}", file=sys.stderr)
        return None

# --------------------------------------
# SCAN
# --------------------------------------
def scan(host, port, args, results):

    result = {"status": "closed", "http": None, "tls": None}
    try:
        socket.create_connection((host, port), timeout=args.timeout).close()
        result["status"] = "open"
    except:
        results.setdefault(host, {})[str(port)] = result
        return

    # HTTP
    if args.http:
        info = http_get(host, port, use_https=(port == 443), timeout=args.timeout)
        result["http"] = info

    # TLS
    if args.tls:
        result["tls"] = get_tls_info(host, port, timeout=args.timeout)

    results.setdefault(host, {})[str(port)] = result

# --------------------------------------
# SAVE OUTPUT
# --------------------------------------
def save_output(results, prefix):
    with open(f"{prefix}.json", "w") as f:
        json.dump({"results": results}, f, indent=2)

    with open(f"{prefix}.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host","port","status","title","server","cert_cn","cert_expires"])

        for host, ports in results.items():
            for port, r in ports.items():
                http = r.get("http") or {}
                tls = r.get("tls") or {}

                writer.writerow([
                    host,
                    port,
                    r["status"],
                    http.get("title", ""),
                    http.get("server_header", ""),
                    tls.get("subject_cn", ""),
                    tls.get("notAfter", "")
                ])

    print(f"Saved -> {prefix}.json and {prefix}.csv")

# --------------------------------------
# MAIN
# --------------------------------------
if __name__ == "__main__":
    args = get_args()

    start_time = time.time()

    targets = load_targets(args.targets)
    ports = parse_ports(args.ports)

    print(f"Scanning {len(targets)} hosts on {len(ports)} ports with {args.workers} workers...")

    results = {}

    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        for host in targets:
            for port in ports:
                exe.submit(scan, host, port, args, results)

    save_output(results, args.output)

    elapsed = time.time() - start_time  
    print(f"Scan completed in {elapsed:.2f} seconds")
