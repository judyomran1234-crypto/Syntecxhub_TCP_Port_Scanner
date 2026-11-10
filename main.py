
#!/usr/bin/env python3

"""
Syntecxhub TCP Port Scanner

A beginner-friendly TCP port scanner.
Only scan computers and networks you own
or have permission to test.
"""

import argparse
import csv
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# Common TCP ports and their services
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    8080: "HTTP-ALT",
}


def parse_ports(port_text):
    """Parse individual ports and port ranges."""

    ports = set()

    for part in port_text.split(","):
        part = part.strip()

        if "-" in part:
            start, end = map(int, part.split("-", 1))

            if start > end:
                raise ValueError("Invalid port range.")

            if start < 1 or end > 65535:
                raise ValueError("Ports must be between 1 and 65535.")

            ports.update(range(start, end + 1))

        else:
            port = int(part)

            if not 1 <= port <= 65535:
                raise ValueError("Ports must be between 1 and 65535.")

            ports.add(port)

    if not ports:
        raise ValueError("No ports were provided.")

    return sorted(ports)


def scan_port(host, port, timeout):
    """Attempt a TCP connection to one port."""

    result = {
        "host": host,
        "port": port,
        "service": COMMON_PORTS.get(port, "Unknown"),
        "status": "closed",
        "detail": ""
    }

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout
        ):
            result["status"] = "open"
            result["detail"] = "Connection successful"

    except socket.timeout:
        result["status"] = "timeout"
        result["detail"] = "Connection timed out"

    except ConnectionRefusedError:
        result["status"] = "closed"
        result["detail"] = "Connection refused"

    except OSError as error:
        result["status"] = "error"
        result["detail"] = str(error)

    return result


def save_results(results, filename):
    """Save scan results to a CSV file."""

    fields = [
        "host",
        "port",
        "service",
        "status",
        "detail"
    ]

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)

        writer.writeheader()
        writer.writerows(results)


def main():

    parser = argparse.ArgumentParser(
        description="Syntecxhub TCP Port Scanner"
    )

    parser.add_argument(
        "host",
        help="Target hostname or IP address"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Port or range, e.g. 80 or 1-1024"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Number of worker threads"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="scan_results.csv",
        help="CSV output filename"
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    if args.timeout <= 0:
        parser.error("Timeout must be greater than zero.")

    if not 1 <= args.workers <= 500:
        parser.error("Workers must be between 1 and 500.")

    try:
        address = socket.gethostbyname(args.host)
    except socket.gaierror:
        print("[ERROR] Could not resolve target hostname.")
        return

    logging.basicConfig(
        filename="scanner.log",
        level=logging.INFO,
        format="%(asctime)s - %(message)s"
    )

    print("=" * 55)
    print("        SYNTEC XHUB TCP PORT SCANNER")
    print("=" * 55)

    print(f"Target: {args.host}")
    print(f"IP Address: {address}")
    print(f"Ports to scan: {len(ports)}")
    print("-" * 55)

    start_time = datetime.now()

    results = []

    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                args.host,
                port,
                args.timeout
            ): port
            for port in ports
        }

        for future in as_completed(futures):

            result = future.result()
            results.append(result)

            logging.info(
                "Host=%s Port=%s Status=%s",
                result["host"],
                result["port"],
                result["status"]
            )

            if result["status"] == "open":

                print(
                    f"[OPEN] {result['port']}/TCP "
                    f"- {result['service']}"
                )

            elif result["status"] == "closed":

                print(
                    f"[CLOSED] {result['port']}/TCP"
                )

            elif result["status"] == "error":

                print(
                    f"[ERROR] {result['port']}/TCP "
                    f"- {result['detail']}"
                )

    results.sort(key=lambda item: item["port"])

    try:
        save_results(results, args.output)
    except OSError as error:
        print(f"[ERROR] Could not save results: {error}")
        return

    elapsed = (datetime.now() - start_time).total_seconds()

    open_count = sum(
        r["status"] == "open" for r in results
    )

    closed_count = sum(
        r["status"] == "closed" for r in results
    )

    timeout_count = sum(
        r["status"] == "timeout" for r in results
    )

    error_count = sum(
        r["status"] == "error" for r in results
    )

    print("-" * 55)
    print("SCAN SUMMARY")
    print(f"Open ports: {open_count}")
    print(f"Closed ports: {closed_count}")
    print(f"Timeouts: {timeout_count}")
    print(f"Errors: {error_count}")
    print(f"Time taken: {elapsed:.2f} seconds")
    print(f"Results saved to: {args.output}")
    print("Detailed log saved to: scanner.log")
    print("=" * 55)


if __name__ == "__main__":
    main()
