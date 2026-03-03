# WebScanX Testing Guide

## Overview

This guide provides comprehensive testing procedures for WebScanX to ensure all components are working correctly.

## Prerequisites

- WebScanX installed and configured
- Python 3.8+ with all dependencies
- Network connectivity
- Permission to test target systems

## Testing Levels

### 1. Unit Testing

Test individual components in isolation.

#### Test HTTP Client
```bash
python3 -c "
import asyncio
from core.config import ConfigManager
from utils.http_client import HTTPClient

async def test():
    config = ConfigManager({'target': 'https://httpbin.org'})
    client = HTTPClient(config)
    await client.initialize()
    response = await client.get('https://httpbin.org/get')
    print(f'Status: {response.status}')
    await client.close()

asyncio.run(test())
"
```

#### Test Configuration Manager
```bash
python3 -c "
from core.config import ConfigManager
config = ConfigManager({'target': 'https://example.com', 'mode': 'standard'})
print(f'Target: {config.get(\"target\")}')
print(f'Mode: {config.get(\"mode\")}')
print('Config test passed!')
"
```

#### Test Report Generator
```bash
python3 -c "
import asyncio
from core.config import ConfigManager
from reports.generator import ReportGenerator

async def test():
    config = ConfigManager({'target': 'https://example.com'})
    gen = ReportGenerator(config)
    
    test_results = {
        'scan_metadata': {
            'target': 'https://example.com',
            'start_time': '2024-01-01T00:00:00',
            'duration': '00:05:30',
            'mode': 'standard'
        },
        'vulnerabilities': [
            {
                'title': 'Test Vulnerability',
                'severity': 'high',
                'description': 'Test description',
                'url': 'https://example.com/test',
                'evidence': ['Evidence 1', 'Evidence 2'],
                'remediation': 'Fix the issue'
            }
        ],
        'assets': []
    }
    
    filepath = await gen.generate(test_results, 'json')
    print(f'Report generated: {filepath}')

asyncio.run(test())
"
```

### 2. Integration Testing

Test component interactions.

#### Test Full Scan Workflow
```bash
# Test with a safe target (httpbin.org)
python3 webscanx.py -t https://httpbin.org --mode standard --format json -o ./test_reports
```

#### Test Silent Mode
```bash
python3 webscanx.py -t https://httpbin.org --mode silent --format json
```

#### Test Deep Mode
```bash
python3 webscanx.py -t https://httpbin.org --mode deep --format json,html
```

#### Test AI Mode
```bash
python3 webscanx.py -t https://httpbin.org --mode ai --ai --format json,html
```

### 3. Module Testing

Test individual scanning modules.

#### Test Reconnaissance Module
```bash
python3 -c "
import asyncio
from core.config import ConfigManager
from core.state import ScanState
from utils.http_client import HTTPClient
from modules.reconnaissance import ReconnaissanceModule

async def test():
    config = ConfigManager({'target': 'https://httpbin.org'})
    state = ScanState(config)
    client = HTTPClient(config)
    await client.initialize()
    
    module = ReconnaissanceModule(config, state, client)
    results = await module.run()
    
    print(f'Reconnaissance results: {len(results.get(\"assets\", []))} assets found')
    await client.close()

asyncio.run(test())
"
```

#### Test Discovery Module
```bash
python3 webscanx.py -t https://httpbin.org --modules discovery --format json
```

#### Test Vulnerability Module
```bash
python3 webscanx.py -t https://httpbin.org --modules vulnerability --format json
```

#### Test WAF Detection
```bash
python3 webscanx.py -t https://httpbin.org --modules waf_detection --format json
```

### 4. Feature Testing

Test specific features.

#### Test Authentication
```bash
# Cookie-based
python3 webscanx.py -t https://httpbin.org/cookies --cookie "test=value"

# Bearer token
python3 webscanx.py -t https://httpbin.org/bearer --auth "Bearer test-token"

# Basic auth
python3 webscanx.py -t https://httpbin.org/basic-auth/user/pass --username user --password pass
```

#### Test Proxy Support
```bash
# Start a local proxy (e.g., Burp Suite on 8080)
python3 webscanx.py -t https://httpbin.org --proxy http://127.0.0.1:8080
```

#### Test Rate Limiting
```bash
python3 webscanx.py -t https://httpbin.org --rate-limit 5 --delay 0.5 -v
```

#### Test Custom Wordlists
```bash
# Create test wordlist
echo -e "get\npost\nput\ndelete" > /tmp/test_wordlist.txt

python3 webscanx.py -t https://httpbin.org -w /tmp/test_wordlist.txt
```

#### Test Report Formats
```bash
# JSON only
python3 webscanx.py -t https://httpbin.org --format json

# HTML only
python3 webscanx.py -t https://httpbin.org --format html

# XML only
python3 webscanx.py -t https://httpbin.org --format xml

# All formats
python3 webscanx.py -t https://httpbin.org --format json,html,xml
```

### 5. AI Testing

Test AI-powered features.

#### Test AI Correlation
```bash
python3 webscanx.py -t https://httpbin.org --mode ai --ai --format json
```

#### Test Pattern Learning
```bash
# Run multiple scans to build learning data
python3 webscanx.py -t https://httpbin.org --mode ai --ai
python3 webscanx.py -t https://httpbin.org/anything --mode ai --ai

# Check learned patterns
ls -la ~/.webscanx/ai_data/
cat ~/.webscanx/ai_data/learned_patterns.json
```

### 6. Performance Testing

Test performance and resource usage.

#### Test Concurrent Requests
```bash
# Low concurrency
python3 webscanx.py -t https://httpbin.org --threads 5

# Medium concurrency
python3 webscanx.py -t https://httpbin.org --threads 10

# High concurrency
python3 webscanx.py -t https://httpbin.org --threads 20
```

#### Test Timeout Handling
```bash
# Short timeout
python3 webscanx.py -t https://httpbin.org/delay/10 --timeout 5

# Long timeout
python3 webscanx.py -t https://httpbin.org/delay/3 --timeout 10
```

#### Test Memory Usage
```bash
# Monitor memory during scan
python3 -m memory_profiler webscanx.py -t https://httpbin.org --mode deep
```

### 7. Error Handling Testing

Test error scenarios.

#### Test Invalid Target
```bash
python3 webscanx.py -t invalid-url
python3 webscanx.py -t http://nonexistent.example.com
```

#### Test Network Errors
```bash
# Unreachable host
python3 webscanx.py -t http://192.0.2.1 --timeout 5

# Invalid port
python3 webscanx.py -t http://httpbin.org:99999
```

#### Test SSL Errors
```bash
# Self-signed certificate
python3 webscanx.py -t https://self-signed.badssl.com/ --verify-ssl false

# Expired certificate
python3 webscanx.py -t https://expired.badssl.com/ --verify-ssl false
```

### 8. Safe Testing Targets

Use these safe, legal targets for testing:

#### Public Testing Sites
- **httpbin.org** - HTTP testing service
- **example.com** - IANA example domain
- **testphp.vulnweb.com** - Intentionally vulnerable PHP site
- **demo.testfire.net** - Intentionally vulnerable banking app
- **juice-shop.herokuapp.com** - OWASP Juice Shop

#### Local Testing
```bash
# Set up local test environment
docker run -d -p 8080:80 vulnerables/web-dvwa
python3 webscanx.py -t http://localhost:8080
```

### 9. Regression Testing

Test for regressions after changes.

#### Create Test Suite
```bash
#!/bin/bash
# test_suite.sh

echo "Running WebScanX Test Suite"
echo "==========================="

# Test 1: Basic functionality
echo "Test 1: Basic scan"
python3 webscanx.py -t https://httpbin.org --format json -o /tmp/test1
if [ $? -eq 0 ]; then echo "✓ PASS"; else echo "✗ FAIL"; fi

# Test 2: Silent mode
echo "Test 2: Silent mode"
python3 webscanx.py -t https://httpbin.org --mode silent --format json -o /tmp/test2
if [ $? -eq 0 ]; then echo "✓ PASS"; else echo "✗ FAIL"; fi

# Test 3: Report generation
echo "Test 3: Report generation"
python3 webscanx.py -t https://httpbin.org --format json,html -o /tmp/test3
if [ -f /tmp/test3/*.json ] && [ -f /tmp/test3/*.html ]; then 
    echo "✓ PASS"
else 
    echo "✗ FAIL"
fi

# Test 4: Configuration file
echo "Test 4: Configuration file"
python3 webscanx.py -t https://httpbin.org --config config/default.yaml
if [ $? -eq 0 ]; then echo "✓ PASS"; else echo "✗ FAIL"; fi

echo "Test suite complete"
```

### 10. Validation Checklist

Before deployment, verify:

- [ ] All modules load without errors
- [ ] HTTP client handles various response codes
- [ ] Reports generate in all formats
- [ ] AI correlation detects patterns
- [ ] Wordlists load correctly
- [ ] Authentication methods work
- [ ] Proxy support functions
- [ ] Rate limiting prevents overload
- [ ] Error handling is graceful
- [ ] Logging captures events
- [ ] Configuration files parse correctly
- [ ] State management saves/resumes
- [ ] Memory usage is reasonable
- [ ] No sensitive data in logs
- [ ] Help documentation is accurate

## Troubleshooting

### Common Issues

#### Import Errors
```bash
# Reinstall dependencies
pip3 install -r requirements.txt --force-reinstall
```

#### Permission Errors
```bash
# Fix permissions
chmod +x webscanx.py
chmod -R 755 ~/.webscanx
```

#### Network Errors
```bash
# Test connectivity
curl -I https://httpbin.org
ping -c 3 httpbin.org
```

#### Report Generation Fails
```bash
# Check output directory
mkdir -p reports
chmod 755 reports
```

## Continuous Testing

### Automated Testing
```bash
# Add to cron for daily testing
0 2 * * * /path/to/webscanx/test_suite.sh >> /var/log/webscanx_tests.log 2>&1
```

### CI/CD Integration
```yaml
# .github/workflows/test.yml
name: WebScanX Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: ./test_suite.sh
```

## Reporting Issues

If you encounter issues:

1. Check logs in `logs/` directory
2. Run with verbose mode: `-vvv`
3. Verify dependencies: `pip3 list`
4. Test with safe target: `https://httpbin.org`
5. Report to: karimalkashif2003@gmail.com

## Legal Notice

⚠️ **IMPORTANT**: Only test systems you have explicit permission to scan. Unauthorized testing is illegal and unethical.

---

**Happy Testing! 🛡️**
