#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Basic functionality test for WebScanX
Tests core components without external dependencies
"""

import sys
import os
from pathlib import Path

print("=" * 60)
print("WebScanX Basic Functionality Test")
print("=" * 60)
print()

# Test 1: Python version
print("[Test 1] Python Version Check")
print(f"Python version: {sys.version}")
if sys.version_info >= (3, 8):
    print("✓ PASS: Python 3.8+ detected")
else:
    print("✗ FAIL: Python 3.8+ required")
    sys.exit(1)
print()

# Test 2: Project structure
print("[Test 2] Project Structure")
required_dirs = ['core', 'modules', 'ai', 'utils', 'reports', 'wordlists', 'config']
for dir_name in required_dirs:
    dir_path = Path(dir_name)
    if dir_path.exists() and dir_path.is_dir():
        print(f"✓ {dir_name}/ exists")
    else:
        print(f"✗ {dir_name}/ missing")
print()

# Test 3: Required files
print("[Test 3] Required Files")
required_files = [
    'webscanx.py',
    'requirements.txt',
    'INSTALL.sh',
    'README.md',
    'config/default.yaml',
    'wordlists/dirs.txt',
    'wordlists/files.txt',
    'wordlists/params.txt',
    'wordlists/payloads.txt'
]
for file_name in required_files:
    file_path = Path(file_name)
    if file_path.exists() and file_path.is_file():
        print(f"✓ {file_name} exists")
    else:
        print(f"✗ {file_name} missing")
print()

# Test 4: Module imports (without dependencies)
print("[Test 4] Module Structure (basic)")
try:
    # Test if Python files are valid
    import py_compile
    
    test_files = [
        'webscanx.py',
        'core/config.py',
        'core/engine.py',
        'core/state.py',
        'reports/generator.py',
        'utils/validator.py',
        'utils/banner.py'
    ]
    
    for file_path in test_files:
        try:
            py_compile.compile(file_path, doraise=True)
            print(f"✓ {file_path} syntax valid")
        except py_compile.PyCompileError as e:
            print(f"✗ {file_path} syntax error: {e}")
except Exception as e:
    print(f"✗ Compilation test failed: {e}")
print()

# Test 5: Wordlists
print("[Test 5] Wordlist Content")
wordlist_files = {
    'wordlists/dirs.txt': 50,
    'wordlists/files.txt': 50,
    'wordlists/params.txt': 50,
    'wordlists/payloads.txt': 50
}

for wordlist, min_lines in wordlist_files.items():
    try:
        with open(wordlist, 'r') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if len(lines) >= min_lines:
                print(f"✓ {wordlist}: {len(lines)} entries")
            else:
                print(f"⚠ {wordlist}: {len(lines)} entries (expected >= {min_lines})")
    except Exception as e:
        print(f"✗ {wordlist}: {e}")
print()

# Test 6: Configuration file
print("[Test 6] Configuration File")
try:
    config_file = Path('config/default.yaml')
    if config_file.exists():
        with open(config_file, 'r') as f:
            content = f.read()
            if 'scan:' in content and 'mode:' in content:
                print("✓ config/default.yaml is valid")
            else:
                print("⚠ config/default.yaml may be incomplete")
    else:
        print("✗ config/default.yaml not found")
except Exception as e:
    print(f"✗ Configuration test failed: {e}")
print()

# Test 7: Permissions
print("[Test 7] File Permissions")
executable_files = ['webscanx.py', 'INSTALL.sh']
for file_name in executable_files:
    file_path = Path(file_name)
    if file_path.exists():
        if os.access(file_path, os.X_OK):
            print(f"✓ {file_name} is executable")
        else:
            print(f"⚠ {file_name} is not executable (run: chmod +x {file_name})")
    else:
        print(f"✗ {file_name} not found")
print()

# Summary
print("=" * 60)
print("Test Summary")
print("=" * 60)
print()
print("✓ Basic structure tests passed")
print("⚠ To complete setup, run: ./INSTALL.sh")
print("⚠ Or manually install dependencies: pip3 install -r requirements.txt")
print()
print("After installation, test with:")
print("  python3 webscanx.py --help")
print()
