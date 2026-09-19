#!/usr/bin/env bash
set -euo pipefail
echo '=============================================='
echo ' Automated IOC Reputation Checker'
echo '        VirusTotal API + Python'
echo '=============================================='
echo
if [[ $# -eq 0 ]]; then
  echo 'Usage: ./scripts/ioc_checker.sh --input dataset/ioc_dataset_500_synthetic.xlsx'
  echo '       ./scripts/ioc_checker.sh --ioc 8.8.8.8'
  echo '       ./scripts/ioc_checker.sh --input dataset/ioc_dataset_500_synthetic.xlsx --dry-run'
  exit 1
fi
python3 scripts/main.py "$@"
