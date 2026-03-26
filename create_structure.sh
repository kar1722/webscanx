#!/bin/bash

# Create the main project directory
mkdir -p webscanx

# Create directories for the main components
mkdir -p webscanx/{tests,logs,configs,src/{security,utils}}

# Create init files
for dir in webscanx tests logs configs src/security src/utils; do
    touch "$dir/__init__.py"
done

# Create placeholder files
for file in README.md version.txt; do
    touch "webscanx/$file"
done

echo "Directory structure for webscanx created successfully!"