User Guide for Recon\_Tool

Introduction

Recon\_Tool is a GUI-based domain reconnaissance tool built with Python and Tkinter. It provides a convenient interface for gathering domain intelligence such as WHOIS info, DNS records, subdomains, port scan results, and technology detection using BuiltWith.

How to Use the Tool

Prerequisites

Ensure the following Python packages are installed:

pip install python-whois dnspython requests builtwith

Also, make sure you are connected to the internet during the scan (especially for WHOIS, subdomains, and technology detection).

Launch the Tool

To run the tool:

python main.py

GUI Overview

Section	Description

Domain	

Enter the domain to scan (e.g., example.com).

Verbosity

Select how detailed the output should be:

0 - Errors Only

1. - Basic Info
1. - Detailed Info

Scan Type	Choose what kind of scan you want:

whois, dns, subdomains, portscan, or all (everything).

Ports	(Only for portscan or all) Enter ports like 80,443 or ranges like 20-90. Default list is used if left empty.

Start Scan	Click to start scanning based on selected options.

Save Report	Save the scan results to a .txt file.

🔍 Scan Types Explained

Scan Type	

whois	

Gets domain registration data like owner, registrar, emails, creation and expiry dates.

dns	

Fetches DNS records: A, MX, NS, and TXT.

subdomains	

Extracts subdomains from the crt.sh certificate database.

portscan	

Checks for open ports and attempts to grab banners (like HTTP headers).

all	

Performs all of the above scans.


Example Usage

Enter example.com as the domain.

Select 2 - Detailed Info for verbosity.

Choose all as scan type.

(Optional) Enter port list like 80,443,8080 or 20-100.

Click Start Scan.

View the results in the main window.

Click Save Report to download the findings.

Saving Reports

After scanning, click Save Report.

Choose a file location and name.

The report will be saved as a .txt file containing all logs shown in the GUI.
