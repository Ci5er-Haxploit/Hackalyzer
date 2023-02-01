import os
import socket
import subprocess
import csv

def arp_scan():
    """Perform an ARP scan to find live hosts on the local network"""
    tool = input("Enter the tool to use for ARP scan (arp-scan or netdiscover): ")
    live_hosts = []
    if tool == "arp-scan":
        arp_scan_output = subprocess.run(["arp-scan", "-l"], capture_output=True).stdout.decode()
        for line in arp_scan_output.splitlines():
            if line.startswith("192.") or line.startswith("10.") or line.startswith("172."):
                ip_address = line.split()[0]
                live_hosts.append(ip_address)
    elif tool == "netdiscover":
        ip_range = input("Enter the IP range for netdiscover (example: 192.168.0.0/24): ")
        netdiscover_output = subprocess.run(["netdiscover", "-r", ip_range], capture_output=True).stdout.decode()
        for line in netdiscover_output.splitlines():
            if line.startswith("192.") or line.startswith("10.") or line.startswith("172."):
                ip_address = line.split()[1]
                live_hosts.append(ip_address)
    else:
        print("Invalid tool entered. Please enter either arp-scan or netdiscover.")
        return None
    return live_hosts

def port_scan(ip_address):
    """Scan an IP address for open ports and running service versions"""
    nmap_output = subprocess.run(["nmap", "-sV", "-O", ip_address], capture_output=True).stdout.decode()
    open_ports = []
    service_versions = []
    os_info = ""
    for line in nmap_output.splitlines():
        if "open" in line:
            port = line.split("/")[0]
            open_ports.append(port)
            serv1=' '.join(line.split())
            serv2=serv1.split(" ", 3)[:4]
            service_version = serv2[-1]
            service_versions.append(service_version)
        elif "Running" in line:
            os_info = line
    return open_ports, service_versions, os_info

def vulnerabilities_scan(ip_address):
    """Scan an IP address for vulnerabilities in the open ports using nmap"""
    vulnerabilities = []
    print("running vulnscan")
    nmap_output = subprocess.run(["nmap", "--script vuln", ip_address], capture_output=True).stdout.decode()
    for line in nmap_output.splitlines():
            if "IDs:" in line:
                vulnerabilities.append(vulnerability)
    return vulnerabilities

def print_scan_results(ip_address, open_ports, service_versions, os_info, vulnerabilities):
    """Print scan results in an user readable manner"""
    print("IP address:", ip_address)
    print("Open ports:", open_ports)
    print("Service versions:", service_versions)
    print("OS info:", os_info)
    print("Vulnerabilities:", vulnerabilities)

def generate_csv_report(ip_address, open_ports, service_versions, os_info, vulnerabilities):
    """Generate a CSV report of the scan results"""
    with open("scan_results.csv", "w") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["IP address", "Open ports", "Service versions", "OS info", "Vulnerabilities"])
        csv_writer.writerow([ip_address, open_ports, service_versions, os_info, vulnerabilities])

def main():
    ip_address = input("Enter an IP address to scan (leave blank to ARP scan the local network): ")
    if not ip_address:
        live_hosts = arp_scan()
        for host in live_hosts:
            open_ports, service_versions, os_info = port_scan(host)
            vulnerabilities = vulnerabilities_scan(host)
            print_scan_results(host, open_ports, service_versions, os_info, vulnerabilities)
            generate_csv_report(host, open_ports, service_versions, os_info, vulnerabilities)
    else:
        open_ports, service_versions, os_info = port_scan(ip_address)
        vulnerabilities = vulnerabilities_scan(ip_address)
        print_scan_results(ip_address, open_ports, service_versions, os_info, vulnerabilities)
        generate_csv_report(ip_address, open_ports, service_versions, os_info, vulnerabilities)

if __name__ == "__main__":
    print('''
                                                    ███████████▓▓▓▓▓▓▓▓▒░░░░░▒▒░░░░░░░▓█████
                                                    █████████▓▓▓▓▓▓▓▓▒░░░░░░▒▒▒░░░░░░░░░▓███
                                                    ███████▓▓▓▓▓▓▓▓▒░░▒▓░░░░░░░░░░░░░░░░░███
                                                   ██████▓▓▓▓▓▓▓▓▒░▓████░░░░░▒▓░░░░░░░░░███
                                                    █████▓▒▓▓▓▓▓▒░▒█████▓░░░░▓██▓░░░░░░░▒███
                                                    ████▓▒▓▒▒▒░░▒███████░░░░▒████░░░░░░░░███
                                                     ███▓▒▒▒░░▒▓████████▒░░░░▓████▒░░░░░░▒███
                                                ██▓▒░░███████████▓░░░░░░▒█████▓░░░░░░███
                                                    ██▓▒░▒██████████▓▒▒▒░░░░░██████▒░░░░░▓██
                                                      ███▒░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░███████▓░░░▓██
                                                    ███▓░░░░░▒▒▒▓▓▒▒▒▒░░░░░░░░░██████▓░░░███
                                                    ████▓▒▒▒▒▓▓▓▓▓▓▒▒▓██▒░░░░░░░▓███▓░░░░███
                                                   ██████████▓▓▓▓▒▒█████▓░░░░░░░░░░░░░░████
                                                    █████████▓▓▓▓▒▒░▓█▓▓██░░░░░░░░░░░░░█████
                                                     ███████▓▓▓▓▓▒▒▒░░░░░░▒░░░░░░░░░░░░██████
                                                    ██████▓▓▓▓▓▓▒▒░░░░░░░░░░░░░░░░▒▓████████
                                                    ██████▓▓▓▓▓▒▒▒░░░░░░░░░░░░░░░▓██████████
                                                ██████▓▓▓▓▒▒██████▒░░░░░░░░░▓███████████
                                                    ██████▓▓▓▒▒█████████▒░░░░░░▓████████████
                                               ██████▓░░████████████░░░░███████████████
                                                    ██████▓░▓███████████▒░░░████████████████
                                                    ██████▓░███████████▓░░░█████████████████
                                                    ██████▓▒██████████░░░███████████████████
                                                    ██████▒▒█████████▒░▓████████████████████
                                                 ██████░▓████████░███████████████████████
                                                    █████▓░███████▒░████████████████████████
                                                     █████▒░███████░▓████████████████████████
                                                    █████░▒█████▓░██████████████████████████
                                                   █████░▓█████░▒██████████████████████████
                                                    █████░▓████▒░███████████████████████████
                                                     ██████░▓▓▒░▓████████████████████████████
                                                    ███████▒░▒██████████████████████████████
                                                  ████████████████████████████████████████
                                                    ████████████████████████████████████████

 ▄  █ ██   ▄█▄    █  █▀ ██   █    ▀▄    ▄ ▄▄▄▄▄▄   ▄███▄   █▄▄▄▄         ▄      ▄      ▄  
█   █ █ █  █▀ ▀▄  █▄█   █ █  █      █  █ ▀   ▄▄▀   █▀   ▀  █  ▄▀     ▀▄   █ ▀▄   █ ▀▄   █ 
██▀▀█ █▄▄█ █   ▀  █▀▄   █▄▄█ █       ▀█   ▄▀▀   ▄▀ ██▄▄    █▀▀▌        █ ▀    █ ▀    █ ▀  
█   █ █  █ █▄  ▄▀ █  █  █  █ ███▄    █    ▀▀▀▀▀▀   █▄   ▄▀ █  █       ▄ █    ▄ █    ▄ █   
   █     █ ▀███▀    █      █     ▀ ▄▀              ▀███▀     █       █   ▀▄ █   ▀▄ █   ▀▄ 
  ▀     █          ▀      █                                 ▀         ▀      ▀      ▀                                       
                                                    
                                                    Created by Ci5er.
                                                    For Educational and R&D purposes only.

''')
    main()
