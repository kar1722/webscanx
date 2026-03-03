#!/bin/bash

# WebScanX - Basic Scan Examples

echo "WebScanX - Basic Scan Examples"
echo "================================"
echo ""

# Example 1: Standard scan
echo "Example 1: Standard Scan"
echo "------------------------"
echo "python3 webscanx.py -t https://example.com"
echo ""

# Example 2: Silent mode
echo "Example 2: Silent Mode (Stealthy)"
echo "----------------------------------"
echo "python3 webscanx.py -t https://example.com --mode silent"
echo ""

# Example 3: Deep analysis
echo "Example 3: Deep Analysis"
echo "------------------------"
echo "python3 webscanx.py -t https://example.com --mode deep"
echo ""

# Example 4: AI-guided scan
echo "Example 4: AI-Guided Scan"
echo "-------------------------"
echo "python3 webscanx.py -t https://example.com --mode ai --ai"
echo ""

# Example 5: With authentication
echo "Example 5: Authenticated Scan"
echo "------------------------------"
echo "python3 webscanx.py -t https://example.com --cookie 'session=abc123'"
echo "python3 webscanx.py -t https://example.com --auth 'Bearer token123'"
echo ""

# Example 6: Custom wordlist
echo "Example 6: Custom Wordlist"
echo "--------------------------"
echo "python3 webscanx.py -t https://example.com -w /path/to/wordlist.txt"
echo ""

# Example 7: Specific modules
echo "Example 7: Specific Modules Only"
echo "---------------------------------"
echo "python3 webscanx.py -t https://example.com --modules reconnaissance,vulnerability"
echo ""

# Example 8: Multiple report formats
echo "Example 8: Multiple Report Formats"
echo "-----------------------------------"
echo "python3 webscanx.py -t https://example.com --format json,html,pdf -o ./reports"
echo ""

# Example 9: With proxy
echo "Example 9: Through Proxy"
echo "------------------------"
echo "python3 webscanx.py -t https://example.com --proxy http://127.0.0.1:8080"
echo ""

# Example 10: Rate limited
echo "Example 10: Rate Limited Scan"
echo "------------------------------"
echo "python3 webscanx.py -t https://example.com --rate-limit 10 --delay 0.5"
echo ""

# Example 11: Verbose output
echo "Example 11: Verbose Output"
echo "--------------------------"
echo "python3 webscanx.py -t https://example.com -vvv"
echo ""

# Example 12: Configuration file
echo "Example 12: Using Configuration File"
echo "-------------------------------------"
echo "python3 webscanx.py -t https://example.com --config config.yaml"
echo ""

echo "For more options, run: python3 webscanx.py --help"
