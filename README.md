


How It Works
ARP Spoofer:

Sends spoofed ARP packets to the victim and the router.
Runs in a separate thread to avoid blocking the main program.
After sending 10 packets, it signals the main thread to start the sniffer.
Packet Sniffer:

Listens for HTTP traffic and extracts URLs and potential username/password combinations.
Starts automatically after the ARP spoofer sends 10 packets.
Port Forwarding:

Enabled automatically to route packets between the victim and the router.
Graceful Exit:

Restores ARP tables if the program is interrupted with CTRL+C.

Key Features
Gateway Identification:

Uses arp -a to identify the gateway automatically.
Network Scan:

Scans the network for connected devices and displays them.
Target Selection:

Allows the user to select a target from the list of scanned devices.
Dynamic Targeting:

Updates victim_ip and router_ip dynamically based on user input.
Combined Functionality:

Integrates ARP spoofing, packet sniffing, and dynamic network scanning.

