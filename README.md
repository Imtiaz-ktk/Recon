   Recon_Tool - GUI-Based Domain Intelligence Scanner

   Recon_Tool is a lightweight, Python-based reconnaissance tool with a graphical interface. It is designed to perform domain information gathering tasks such as WHOIS lookup, DNS resolution, subdomain enumeration, port scanning with banner grabbing, and technology detection.

---

   Features

- WHOIS – Domain registrar, owner, and expiry details
- DNS Record Fetching – A, MX, NS, TXT records
- Subdomain Enumeration – Uses `crt.sh` for certificate-based discovery
- Port Scanning – Checks specified ports and grabs service banners
- Technology Detection – Detects technologies used by the website (via BuiltWith)
- Export Results – Save scan reports to text files
- Verbosity Control – Set level of detail (errors only, basic, or detailed)

---

  Installation

  Requirements

Ensure Python 3.8+ is installed. Then install required packages:

```bash
pip install -r requirements.txt
