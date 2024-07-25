from scapy.all import ARP, Ether, srp
import socket

def scan_network(ip_range):
    """
    Scans the network for active devices using ARP requests.

    Parameters:
    ip_range (str): The IP range to scan (e.g., "192.168.1.0/24").

    Returns:
    list: A list of dictionaries containing IP and MAC addresses of active devices.
    """
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = broadcast/arp_request
    answered_list = srp(arp_request_packet, timeout=1, verbose=False)[0]

    live_devices = []
    for element in answered_list:
        live_devices.append({'IP': element[1].psrc, 'MAC': element[1].hwsrc})
    
    return live_devices

def scan_ports(ip):
    """
    Scans common ports on a given IP address to find open ports.

    Parameters:
    ip (str): The IP address to scan.

    Returns:
    list: A list of open ports on the given IP address.
    """
    common_ports = [22, 80, 443, 21]
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def main():
    """
    Main function to execute network scanning and port scanning.
    """
    ip_range = "192.168.1.0/24"  # Change this to your network range
    print("Scanning network...")
    live_devices = scan_network(ip_range)
    
    for device in live_devices:
        print(f"Device IP: {device['IP']}, MAC: {device['MAC']}")
        print("Scanning ports...")
        open_ports = scan_ports(device['IP'])
        print(f"Open ports: {open_ports}")

if __name__ == "__main__":
    main()
