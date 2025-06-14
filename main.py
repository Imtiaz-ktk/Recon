from tkinter import *
from tkinter import ttk, filedialog
import whois
import dns.resolver
import requests
import socket
import builtwith
from datetime import datetime

# Get timestamp
def timestamp():
    return datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")

# Logging with verbosity

def log(msg, level=1):
    selected = verbosity_box.get()
    current_level = int(selected.split(" ")[0])  # Extract verbosity number
    if level <= current_level:
        textarea.insert(END, f"{timestamp()} {msg}\n")
        textarea.see(END)

# Function: Port scanning + banner grabbing
def scan_ports_and_grab_banners(domain, port_list):
    log(f"Starting port scan for {domain}", level=1)
    try:
        ip = socket.gethostbyname(domain)
        log(f"Resolved IP: {ip}", level=1)

        for port in port_list:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        s.sendall(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode())

                        banner = s.recv(1024).decode('utf-8', errors='ignore')
                        log(f"[+] Port {port} OPEN", level=2)
                        log(f"Banner:\n{banner}", level=2)
                    except:
                        log(f"[+] Port {port} OPEN (No banner received)", level=2)
                else:
                    log(f"[-] Port {port} CLOSED or filtered", level=2)
                s.close()
            except Exception as e:
                log(f"[-] Error checking port {port}: {e}", level=0)

    except Exception as e:
        log(f"Port scan failed: {e}", level=0)

# Main function triggered on button press
def run_scan():
    domain = label1_entry.get().strip()
    scan_type = scan_type_box.get()
    ports_input = port_entry.get().strip()
    textarea.delete(1.0, END)

    if not domain:
        log("Please enter a domain name.", level=0)
        return

    # WHOIS
    if scan_type in ['whois', 'all']:
        log("=== Whois Info ===", level=1)
        try:
            info = whois.whois(domain)
            log(f"Domain Name: {info.get('domain_name', 'Not Found')}", level=2)
            log(f"Owner: {info.get('name', 'Not Found')}", level=2)
            log(f"Registrar: {info.get('registrar', 'Not Found')}", level=2)
            log(f"Created On: {info.get('creation_date', 'Not Found')}", level=2)
            log(f"Expires On: {info.get('expiration_date', 'Not Found')}", level=2)
            log(f"Email: {info.get('emails', 'Not Found')}", level=2)
            log(f"Name Servers: {info.get('name_servers', 'Not Found')}", level=2)
            log(f"Status: {info.get('status', 'Not Found')}", level=2)
        except Exception as e:
            log(f"Whois lookup failed: {e}", level=0)

    # DNS
    if scan_type in ['dns', 'all']:
        log("=== DNS Info ===", level=1)
        types = ['A', 'MX', 'NS', 'TXT']
        for record_type in types:
            log(f"--- {record_type} Records ---", level=1)
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    log(str(rdata), level=2)
            except Exception as e:
                log(f"{record_type} lookup failed: {e}", level=0)

    # Subdomains
    if scan_type in ['subdomains', 'all']:
        log("=== Subdomains Info ===", level=1)
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            data = requests.get(url).json()
            subdomains = sorted({entry['name_value'] for entry in data})
            for sub in subdomains:
                log(sub, level=2)
        except Exception as e:
            log(f"Subdomain lookup failed: {e}", level=0)

    # Port scan + banner grabbing
    if scan_type in ['portscan', 'all']:
        log("=== Port Scan + Banner Grabbing ===", level=1)
        if ports_input:
            try:
                ports = []
                for part in ports_input.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        ports.extend(range(start, end + 1))
                    elif part.isdigit():
                        ports.append(int(part))
            except:
                log("Invalid port list format. Use 80,443 or ranges like 20-90", level=0)
                return
        else:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

        scan_ports_and_grab_banners(domain, ports)

    # Technology detection
    if scan_type in ['all']:
        log("=== Technology Detected (BuiltWith) ===", level=1)
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36'
            }
            try:
                response = requests.get(f"https://{domain}", headers=headers, timeout=10)
                url_used = response.url
            except Exception:
                response = requests.get(f"http://{domain}", headers=headers, timeout=10)
                url_used = response.url

            if response.status_code == 200:
                tech_info = builtwith.parse(url_used)
                if tech_info:
                    for tech, items in tech_info.items():
                        log(f"{tech}: {', '.join(items)}", level=2)
                else:
                    log("No technologies detected.", level=1)
            else:
                log(f"HTTP response: {response.status_code}", level=1)
        except Exception as e:
            log(f"Technology detection failed: {e}", level=0)

# Save report function
def save_report():
    content = textarea.get(1.0, END).strip()
    if not content:
        log("No content to save.", level=0)
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")],
        title="Save Report As"
    )
    if file_path:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            log(f"Report saved to: {file_path}", level=1)
        except Exception as e:
            log(f"Error saving file: {e}", level=0)

# GUI Setup
root = Tk()
root.title(' Reconnaissance Tool ')
root.geometry('770x570')
root.config(background='#f0f0f0')

root.resizable(False, False)

# Domain input
Label(root, text="Domain:", font='arial 13 bold', bg='teal', fg='white').place(x=25, y=10)
label1_entry = Entry(root, font='arial 13', bd=3)
label1_entry.place(x=120, y=10, width=200)

# Verbosity selection
Label(root, text="Verbosity:", font='arial 13 bold', bg='teal', fg='white').place(x=330, y=10)
verbosity_options = ['0 - Errors Only', '1 - Basic Info', '2 - Detailed Info']
verbosity_box = ttk.Combobox(root, values=verbosity_options, font='arial 12', state='readonly')
verbosity_box.place(x=430, y=10, width=180)
verbosity_box.set('1 - Basic Info')

# Scan type selection
Label(root, text="Scan Type:", font='arial 13 bold', bg='teal', fg='white').place(x=25, y=50)
options = ['whois', 'dns', 'subdomains', 'portscan', 'all']
scan_type_box = ttk.Combobox(root, values=options, font='arial 12', state='readonly')
scan_type_box.place(x=120, y=50, width=200)
scan_type_box.set('whois')

# Port input
Label(root, text="Ports (comma-separated or ranges):", font='arial 13 bold', bg='teal', fg='white').place(x=330, y=50)
port_entry = Entry(root, font='arial 13', bd=3)
port_entry.place(x=610, y=50, width=130)

# Start scan button
button1 = Button(root, text='Start Scan', font='arial 13 bold', bg='yellow', command=run_scan)
button1.place(x=610, y=10, height=30)

# Output text area
textarea = Text(root, font='consolas 11', bg='#e6f2ff', bd=4, relief=SUNKEN)
textarea.place(x=25, y=100, height=400, width=720)

# Save report button
save_button = Button(root, text='Save Report', font='arial 12 bold', bg='lightgreen', command=save_report)
save_button.place(x=610, y=510, height=25, width=130)

root.mainloop()
