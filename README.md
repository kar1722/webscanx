# WebScanX - Advanced Web Application Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-purple.svg" alt="Platform">
</p>

WebScanX is a comprehensive, AI-powered web application security testing framework designed for professional penetration testers and security researchers. It features multiple scanning modes, intelligent analysis, and professional report generation.

## 🌟 Features

### Scanning Modes
- **Silent Mode**: Stealthy reconnaissance with minimal footprint
- **Standard Mode**: Balanced scanning with comprehensive coverage
- **Deep Mode**: In-depth analysis with correlation and chaining
- **AI-Guided Mode**: Intelligent scanning with AI-powered analysis

### Core Capabilities
- 🔍 **Reconnaissance**: DNS enumeration, subdomain discovery, technology fingerprinting
- 🗺️ **Attack Surface Mapping**: Directory brute-forcing, file discovery, API enumeration
- 🛡️ **Vulnerability Detection**: SQLi, XSS, RCE, LFI, IDOR, and more
- 🔥 **WAF/IPS Detection**: Identify and analyze protection mechanisms
- 🤖 **AI Analysis**: Correlation, pattern recognition, intelligent prioritization
- 📊 **Professional Reports**: HTML, JSON, XML, PDF formats

### Advanced Features
- **Modular Architecture**: Easy to extend with custom modules
- **State Management**: Pause and resume scans
- **Rate Limiting**: Avoid overwhelming targets
- **Proxy Support**: Route traffic through proxies
- **Authentication**: Support for various auth methods
- **Learning System**: Improves accuracy over time

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Kali Linux (recommended) or any Linux distribution

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/security-team/webscanx.git
cd webscanx

# Install Python dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x webscanx.py
```

### Optional Dependencies

For PDF report generation:
```bash
sudo apt-get install libpango1.0-0 libffi-dev shared-mime-info
pip3 install weasyprint
```

## 📖 Usage

### Basic Usage

```bash
# Standard scan
python3 webscanx.py -t https://example.com

# Silent mode (stealthy)
python3 webscanx.py -t https://example.com --mode silent

# Deep analysis
python3 webscanx.py -t https://example.com --mode deep

# AI-guided scanning
python3 webscanx.py -t https://example.com --mode ai --ai
```

### Advanced Usage

```bash
# Authenticated scanning
python3 webscanx.py -t https://example.com --cookie "session=abc123"

# With custom wordlist
python3 webscanx.py -t https://example.com -w /path/to/wordlist.txt

# Specific modules only
python3 webscanx.py -t https://example.com --modules reconnaissance,vulnerability

# Custom output formats
python3 webscanx.py -t https://example.com --format json,html,pdf -o ./reports

# With proxy
python3 webscanx.py -t https://example.com --proxy http://127.0.0.1:8080

# Rate limited scanning
python3 webscanx.py -t https://example.com --rate-limit 10 --delay 0.5
```

### Command Line Options

```
Required Arguments:
  -t, --target          Target URL or domain to scan

Scan Modes:
  --mode                Scanning mode (silent, standard, deep, ai)

AI Options:
  --ai                  Enable AI-powered analysis
  --ai-model            AI model to use

Authentication:
  --auth                Authentication header
  --cookie              Cookie string
  --username            Username for basic auth
  --password            Password for basic auth

Scan Options:
  --threads             Number of concurrent threads (default: 10)
  --timeout             Request timeout in seconds (default: 30)
  --delay               Delay between requests
  --user-agent          Custom User-Agent
  --proxy               Proxy URL

Wordlists:
  -w, --wordlist        Custom wordlist
  --payloads            Custom payload file

Report Options:
  --format              Report formats (json,html,pdf,xml)
  -o, --output          Output directory

Control Options:
  --resume              Resume interrupted scan
  -v, --verbose         Increase verbosity
  -q, --quiet           Suppress output
  --config              Load configuration from file
```

## 📁 Project Structure

```
webscanx/
├── webscanx.py           # Main entry point
├── core/                 # Core components
│   ├── config.py         # Configuration management
│   ├── engine.py         # Scan engine
│   └── state.py          # State management
├── modules/              # Scanning modules
│   ├── base.py           # Base module class
│   ├── reconnaissance.py # Reconnaissance module
│   ├── discovery.py      # Content discovery
│   ├── vulnerability.py  # Vulnerability scanner
│   └── waf_detection.py  # WAF detection
├── ai/                   # AI components
│   └── analyzer.py       # AI analysis engine
├── utils/                # Utilities
│   ├── http_client.py    # HTTP client
│   ├── logger.py         # Logging
│   └── validator.py      # Input validation
├── reports/              # Report generation
│   └── generator.py      # Report generator
├── config/               # Configuration files
│   └── default.yaml      # Default configuration
├── wordlists/            # Default wordlists
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## 🔧 Configuration

WebScanX can be configured via:
1. Command line arguments
2. Configuration file (YAML/JSON)
3. Environment variables

### Example Configuration File

```yaml
scan:
  mode: standard
  threads: 10
  timeout: 30
  delay: 0

auth:
  enabled: true
  type: bearer
  token: "your-token-here"

ai:
  enabled: true
  correlation_enabled: true
  learning_enabled: true

report:
  formats:
    - json
    - html
  output_dir: ./reports
```

Load configuration:
```bash
python3 webscanx.py -t https://example.com --config config.yaml
```

## 📊 Report Samples

### HTML Report
The HTML report includes:
- Executive summary with visual charts
- Detailed vulnerability descriptions
- Evidence and remediation guidance
- Risk assessment and prioritization

### JSON Report
Machine-readable format for integration with other tools:
```json
{
  "scan_info": {
    "target": "https://example.com",
    "scan_id": "scan_20240101_120000_abc123"
  },
  "findings": [
    {
      "id": "SQLI001",
      "title": "SQL Injection Vulnerability",
      "severity": "critical",
      ...
    }
  ]
}
```

## 🤖 AI Features

### Correlation Analysis
The AI engine identifies relationships between findings:
- Attack chain detection
- Vulnerability clustering
- Risk amplification

### Pattern Recognition
- Technology-specific vulnerability patterns
- False positive detection
- Anomaly detection

### Learning System
WebScanX learns from each scan:
- Reduces false positives over time
- Improves detection accuracy
- Adapts to target behavior

Enable AI features:
```bash
python3 webscanx.py -t https://example.com --mode ai --ai
```

## 🛡️ Security Considerations

- **Legal**: Only scan systems you have permission to test
- **Rate Limiting**: Use `--rate-limit` and `--delay` to avoid overwhelming targets
- **Stealth**: Use `--mode silent` for minimal footprint
- **Data**: Scan results may contain sensitive information - handle securely

## 🔍 Troubleshooting

### Common Issues

**SSL Certificate Errors**
```bash
# Disable SSL verification
python3 webscanx.py -t https://example.com --verify-ssl false
```

**Connection Timeouts**
```bash
# Increase timeout
python3 webscanx.py -t https://example.com --timeout 60
```

**Rate Limiting**
```bash
# Add delays between requests
python3 webscanx.py -t https://example.com --delay 1 --rate-limit 5
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see LICENSE file for details.

## ⚠️ Disclaimer

WebScanX is intended for authorized security testing only. Unauthorized scanning of systems is illegal. The authors are not responsible for misuse of this tool.

## 📧 Contact

For questions or suggestions:
- Email: security-team@example.com
- GitHub Issues: https://github.com/security-team/webscanx/issues

---

<p align="center">
  <strong>Built with ❤️ by the Security Research Team</strong>
</p>
