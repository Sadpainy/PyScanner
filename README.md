# PyScanner
![Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-red?style=plastic)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=plastic&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=plastic&logo=python&logoColor=white)
![Build Passing](https://img.shields.io/badge/build-passing-brightgreen?style=plastic)
![Termux](https://img.shields.io/badge/Termux-000000?style=plastic&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0OCIgaGVpZ2h0PSI0OCIgdmlld0JveD0iMCAwIDQ4IDQ4Ij48cGF0aCBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGQ9Im0xMC41IDI1LjMyNyAxMC4xMjcgNS44NTNMMTAuNSAzNy4wMzJtMjIgMEgyMS42NzMiLz48cmVjdCB3aWR0aD0iMzciIGhlaWdodD0iMzciIHg9IjUuNSIgeT0iNS41IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIHJ4PSI0IiByeT0iNCIvPjwvc3ZnPg%3D%3D&logoColor=white&labelColor=555555)
![Tests](https://img.shields.io/badge/Tests-passing-brightgreen?style=plastic&labelColor=555555)


pyScanner is a domain reconnaissance tool written in Python. It takes a domain name and tells you what is behind it.

Give it a host, and it resolves the name, scans a set of TCP ports, performs a TLS handshake if HTTPS is available, fetches the HTTP response, and pulls WHOIS registration data. Everything happens in one run, and the result is printed as a clean summary.

It works from a terminal, supports batch scanning from a file, can export results to JSON, CSV, or JSONL, and includes an interactive shell for running individual checks one at a time.

The tool is built on the Python standard library. No external dependencies are required. DNS resolution, port scanning, TLS handshakes, HTTP parsing, and WHOIS queries are all implemented directly.

## What it does

Resolves a domain to its IP addresses.

Scans common TCP ports and reports which ones are open.

Performs a TLS handshake on port 443 and reports the protocol version, cipher, and certificate details.

Sends an HTTP request and reports the status code, server header, page title, redirect target, and body size.

Queries WHOIS servers and extracts registrar, creation date, expiry date, nameservers, and status fields.

Optionally follows HTTP redirects.

Optionally runs against a list of hosts read from a file.

Exports results as JSON, CSV, or JSONL.

Runs an interactive shell for resolving, port scanning, HTTP probing, WHOIS lookups, and full scans on demand.

## How to run

Scan a single domain.

```
python3 pyScanner.py example.com
```

Scan multiple domains.

```
python3 pyScanner.py example.com example.org example.net
```

Scan a list of hosts from a file.

```
python3 pyScanner.py -f hosts.txt
```

Scan a custom range of ports.

```
python3 pyScanner.py example.com -p 80,443,8000-8100
```

Export results to JSON.

```
python3 pyScanner.py example.com -o result.json
```

## Requirements

Python 3.10

## License

Apache 2.0 License

**Made by OvO**

## Notes

pyScanner is intended for learning and for scanning hosts you own or have permission to test. Do not point it at systems you are not authorized to probe.
