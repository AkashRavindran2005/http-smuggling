# NetScapeX - HTTP Request Smuggling Detection Tool

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Development-orange.svg" alt="Status">
</p>

An automated HTTP Request Smuggling vulnerability detection and exploitation framework.

## 🎯 Features

- **Multi-Variant Detection**: CL.TE, TE.CL, TE.TE, H2.CL smuggling detection
- **Raw Socket Client**: No HTTP library abstractions - full control over requests
- **Timing-Based Detection**: Accurate desynchronization confirmation
- **Payload Generator**: Automated payload crafting with obfuscation techniques
- **Target Profiling**: Server/proxy fingerprinting
- **Evidence-Based Reports**: Detailed vulnerability documentation

## 📁 Project Structure

```
http-smuggling/
├── main.py                 # CLI entry point
├── config.py               # Configuration settings
├── requirements.txt        # Python dependencies
│
├── core/                   # Core utilities
│   ├── __init__.py
│   ├── connection.py       # Raw socket HTTP client
│   ├── parser.py           # HTTP response parser
│   └── timing.py           # Timing utilities
│
├── scanner/                # Detection engine
│   ├── __init__.py
│   ├── profiler.py         # Target fingerprinting
│   └── detector.py         # Desync detection logic
│
├── payloads/               # Payload generation
│   ├── __init__.py
│   ├── generator.py        # Payload crafting engine
│   └── templates/          # Payload templates
│       ├── cl_te.py
│       ├── te_cl.py
│       └── te_te.py
│
├── exploits/               # Exploit modules
│   ├── __init__.py
│   ├── cache_poison.py     # Cache poisoning attacks
│   └── request_hijack.py   # Request hijacking
│
├── reports/                # Report generation
│   ├── __init__.py
│   └── generator.py        # Report builder
│
└── tests/                  # Test suite
    ├── __init__.py
    └── test_payloads.py
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
cd http-smuggling

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a single target
python main.py scan --target https://example.com

# Scan with specific techniques
python main.py scan --target https://example.com --techniques cl-te,te-cl

# Generate report
python main.py scan --target https://example.com --report report.html

# Verbose mode
python main.py scan --target https://example.com -v
```

## 🔬 Detection Techniques

### CL.TE (Content-Length / Transfer-Encoding)

Front-end prioritizes `Content-Length`, back-end prioritizes `Transfer-Encoding`.

### TE.CL (Transfer-Encoding / Content-Length)

Front-end prioritizes `Transfer-Encoding`, back-end prioritizes `Content-Length`.

### TE.TE (Transfer-Encoding Obfuscation)

Both servers use `Transfer-Encoding`, but obfuscation tricks cause parsing differences.

## ⚠️ Legal Disclaimer

This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

## 📚 Resources

- [HTTP Desync Attacks - PortSwigger Research](https://portswigger.net/research/http-desync-attacks)
- [RFC 7230 - HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.
