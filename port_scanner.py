import socket
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor
import os
import re

def get_local_ip():
    """Get the local IP address of the machine"""
    try:
        # Create a socket connection to a public DNS server to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def get_network_devices(base_ip):
    """Scan the local network for connected devices"""
    devices = []
    network = ipaddress.ip_network(f"{base_ip}/24", strict=False)
    
    def check_device(ip):
        try:
            # Try to get hostname
            hostname = socket.gethostbyaddr(str(ip))[0]
        except (socket.herror, socket.gaierror):
            hostname = "Unknown"
        
        # Ping the device to check if it's online (only 1 ping with 100ms timeout)
        try:
            subprocess.check_output(f"ping -n 1 -w 100 {ip}", shell=True)
            devices.append((str(ip), hostname))
        except subprocess.CalledProcessError:
            pass
    
    print("Scanning network for devices...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        for ip in network.hosts():
            executor.submit(check_device, ip)
    
    return devices

def scan_ports(ip, start_port=1, end_port=1024):
    """Scan ports on a specific device"""
    open_ports = []
    
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    open_ports.append((port, service))
        except Exception:
            pass
    
    print(f"\nScanning ports {start_port}-{end_port} on {ip}...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(check_port, port)
    
    return sorted(open_ports, key=lambda x: x[0])

def display_devices(devices):
    """Display found devices in a numbered list"""
    print("\nFound devices in your local network:")
    for i, (ip, hostname) in enumerate(devices, 1):
        print(f"{i}. {hostname} ({ip})")

def main():
    print("Windows Local Network Port Scanner")
    print("---------------------------------")
    
    # Get local IP and network
    local_ip = get_local_ip()
    print(f"Your local IP address: {local_ip}")
    
    # Get network devices
    base_ip = ".".join(local_ip.split(".")[:3] + ["0"])
    devices = get_network_devices(base_ip)
    
    if not devices:
        print("No devices found on the local network.")
        return
    
    display_devices(devices)
    
    # Let user select a device
    while True:
        try:
            choice = input("\nEnter the number of the device to scan (or 'q' to quit): ")
            if choice.lower() == 'q':
                return
            
            choice = int(choice)
            if 1 <= choice <= len(devices):
                selected_ip, selected_name = devices[choice - 1]
                break
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")
    
    # Scan ports on selected device
    print(f"\nSelected device: {selected_name} ({selected_ip})")
    open_ports = scan_ports(selected_ip, 1, 1024)  # Scanning well-known ports (1-1024)
    
    if open_ports:
        print("\nOpen ports found:")
        print("Port\tService")
        print("----\t-------")
        for port, service in open_ports:
            print(f"{port}\t{service}")
    else:
        print("\nNo open ports found in the scanned range (1-1024).")
    
    print("\nScan complete.")

if __name__ == "__main__":
    main()