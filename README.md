
# Syntecxhub TCP Port Scanner

## Project Overview

A Python-based TCP Port Scanner developed as part
of the Syntecxhub Cybersecurity Internship.

The project checks TCP ports on a target host to
identify open, closed, and unresponsive ports.

## Features

- TCP port scanning
- Single port scanning
- Port range scanning
- Multithreading
- Common service identification
- Timeout handling
- Exception handling
- CSV report generation
- Logging scan results

## Technologies Used

- Python
- Socket Programming
- ThreadPoolExecutor
- CSV
- Logging

## Requirements

Python 3.9 or newer.

No additional packages are required.

## How to Run

Scan your own computer:

```bash
python main.py 127.0.0.1 -p 1-1024
```

Scan selected ports:

```bash
python main.py 127.0.0.1 -p 22,80,443
```

Scan one port:

```bash
python main.py 127.0.0.1 -p 80
```

## Output

The scanner generates:

- scan_results.csv
- scanner.log

## Responsible Use

This tool is intended for educational purposes.

Only scan systems that you own or have explicit
permission to test.

Do not scan unauthorized networks or devices.
