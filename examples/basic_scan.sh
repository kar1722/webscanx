#!/bin/bash
# Basic WebScanX Scan Examples

echo "WebScanX Basic Scan Examples"
echo "============================="
echo ""

# Example 1: Basic scan
echo "Example 1: Basic scan"
echo "python3 webscanx.py -t https://example.com"
echo ""

# Example 2: Silent mode (stealthy)
echo "Example 2: Silent mode (stealthy)"
echo "python3 webscanx.py -t https://example.com --mode silent"
echo ""

# Example 3: Deep analysis
echo "Example 3: Deep analysis"
echo "python3 webscanx.py -t https://example.com --mode deep"
echo ""

# Example 4: AI-guided scanning
echo "Example 4: AI-guided scanning"
echo "python3 webscanx.py -t https://example.com --mode ai --ai"
echo ""

# Example 5: Authenticated scan
echo "Example 5: Authenticated scan with cookie"
echo "python3 webscanx.py -t https://example.com --cookie 'session=abc123'"
echo ""

# Example 6: Scan with custom wordlist
echo "Example 6: Custom wordlist"
echo "python3 webscanx.py -t https://example.com -w /usr/share/wordlists/dirb/common.txt"
echo ""

# Example 7: Generate multiple report formats
echo "Example 7: Multiple report formats"
echo "python3 webscanx.py -t https://example.com --format json,html,xml -o ./reports"
echo ""

# Example 8: Scan with proxy (e.g., Burp Suite)
echo "Example 8: Scan through proxy"
echo "python3 webscanx.py -t https://example.com --proxy http://127.0.0.1:8080"
echo ""

# Example 9: Rate-limited scanning
echo "Example 9: Rate-limited scanning"
echo "python3 webscanx.py -t https://example.com --rate-limit 10 --delay 0.5"
echo ""

# Example 10: Specific modules only
echo "Example 10: Specific modules"
echo "python3 webscanx.py -t https://example.com --modules reconnaissance,vulnerability"
echo ""

# Example 11: Full scan with all features
echo "Example 11: Full comprehensive scan"
echo "python3 webscanx.py -t https://example.com \\"
echo "    --mode deep \\"
echo "    --ai \\"
echo "    --threads 20 \\"
echo "    --format json,html \\"
echo "    -o ./reports \\"
echo "    --verbose"
echo ""
