# Installation Guide

## 1. Prerequisites
- Python 3.9 or newer
- Nmap installed and on your system PATH
  - Linux: `sudo apt install nmap`
  - macOS: `brew install nmap`
  - Windows: download the installer from https://nmap.org/download.html

## 2. Clone the repository
```bash
git clone https://github.com/<your-username>/ReconMaster.git
cd ReconMaster
```

## 3. Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate
```

## 4. Install dependencies
```bash
pip install -r requirements.txt
```

## 5. Verify Nmap is reachable
```bash
nmap --version
```

## 6. Run ReconMaster
```bash
python main.py
```

## Privileges
SYN scan, OS detection, and several firewall-analysis techniques require
raw socket access:
- Linux/macOS: run with `sudo python main.py`
- Windows: run your terminal as Administrator
