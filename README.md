# Recon Tool – Assignment 2

## Project Overview
A multithreaded network recon tool that scans hosts and ports, collects HTTP info and TLS certificate data, and saves results in JSON and CSV formats.

## Requirements
- Python 3.7+  
- Built-in Python modules: 
import argparse
import socket
import ssl
import json
import csv
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time
import http.client
import base64
import tempfile
import os
import sys
 

## Running the Code
To run the recon tool, provide a targets file, port list, and enable the features you want e.g.: 
python recon.py --targets targets.txt --ports 80,443 --http --tls --workers 50 --output demo

### Command-Line Arguments
| Option        | Description |
------------------------------------------------------------------------
| `--targets`   | File with hostnames or IP addresses (one per line) 
| `--ports`     | Ports to scan (e.g., `80,443`) 
| `--http`      | Enable HTTP fingerprinting (title + server header) 
| `--tls`       | Enable TLS certificate retrieval (CN + expiration) 
| `--workers`   | Number of threads to use (default: 20) 
| `--output`    | Output file prefix (e.g. `demo`) 

## Features Implemented
- **TCP Port Scan**: Determines whether ports are open or closed  
- **HTTP Fingerprinting** (`--http`):  
  - Retrieves page title (`<title>` tag)  
  - Reads the `Server:` HTTP header
- **TLS Certificate Info** (`--tls`):  
  - Extracts the certificate common name (CN)  
  - Extracts certificate expiration date  
- **Multithreading**: Uses `ThreadPoolExecutor` to scan multiple hosts/ports in parallel 
- **JSON + CSV Output**: Saves results in .JSON and easy-to-read .CSV formats   
- **Configurable Timeout and Worker Count**. --timeout 'x amount' --workers 'x amount'


## Video Demo
- Link: [text](https://www.youtube.com/watch?v=Q8oQk4zSUKQ)