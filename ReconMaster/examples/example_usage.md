# Example Usage

## Interactive mode
```bash
python main.py
```

## CLI mode examples
```bash
# Host discovery across a /24
python main.py --cli --target 192.168.1.0/24 --scan discovery

# Fast port scan with a TXT report
python main.py --cli --target 192.168.1.10 --scan fast --format txt

# Service/version detection, all report formats
python main.py --cli --target scanme.nmap.org --scan version --format all

# NSE category scan
python main.py --cli --target scanme.nmap.org --scan nse --nse-category http --format html

# Vulnerability scan with a PDF report
python main.py --cli --target scanme.nmap.org --scan vuln --format pdf
```

## Safe test target
`scanme.nmap.org` is maintained by the Nmap project specifically for
testing scanners against. Do not scan hosts you do not own or have
authorization to test.
