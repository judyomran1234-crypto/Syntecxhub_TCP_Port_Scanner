
# TCP Port Scanner

**A multithreaded TCP port scanning tool developed using Python as part of the Syntecxhub Cybersecurity Internship.**

---

## Overview

This project is a Python-based TCP Port Scanner designed to identify open, closed, and unresponsive TCP ports on a target host.

It uses socket programming and multithreading to perform efficient port scanning.

## Key Features

- TCP port scanning
- Single port and port range scanning
- Multithreading using ThreadPoolExecutor
- Common service identification
- Configurable connection timeout
- Exception handling
- CSV report generation
- Logging

## Technologies Used

- Python
- Socket Programming
- ThreadPoolExecutor
- CSV
- Logging
- Argparse

## Project Structure

```text
Syntecxhub_TCP_Port_Scanner/
│
├── main.py
├── README.md
└── .gitignore
```

## Installation

Clone the repository:

```bash
git clone https://github.com/judyomran1234-crypto/Syntecxhub_TCP_Port_Scanner.git
```

Navigate to the project folder:

```bash
cd Syntecxhub_TCP_Port_Scanner
```

## Usage

Scan your local machine:

```bash
python main.py 127.0.0.1 -p 1-1024
```

Scan selected ports:

```bash
python main.py 127.0.0.1 -p 22,80,443
```

Scan a single port:

```bash
python main.py 127.0.0.1 -p 80
```

## Output

The scanner generates:

- `scan_results.csv` – Stores scan results.
- `scanner.log` – Records scanning activity.

## Responsible Use

This project is intended for educational purposes and authorized security testing.

Only scan systems you own or have explicit permission to test.

---

**Developed as part of the Syntecxhub Cybersecurity Internship.**

