from scapy.all import *
from termcolor import colored

# Ask user for output file
output_file = input("Enter the filename to save output (e.g., output.txt): ")
log_file = open(output_file, "w")

def log_and_print(msg, color=None):
    if color:
        print(colored(msg, color))
    else:
        print(msg)
    log_file.write(msg + "\n")

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        flags = packet[TCP].flags

        if flags == "S":
            log_and_print(f"TCP Handshake Initiated: {src} -> {dst}", 'yellow')
        elif flags == "SA":
            log_and_print(f"TCP Handshake Response: {src} -> {dst}", 'green')
        elif flags == "A":
            log_and_print(f"TCP Handshake Completed: {src} -> {dst}", 'cyan')

        if packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode(errors="ignore")
            if "HTTP" in raw_data:
                log_and_print(f"HTTP Request/Response from {src} -> {dst}", 'blue')
                log_and_print(f"Data: {raw_data[:100]}", 'magenta')

    if packet.haslayer(DNS) and packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        dns_data = packet[DNS].summary()
        log_and_print(f"DNS Query from {src} -> {dst}", 'green')
        log_and_print(f"DNS Details: {dns_data}", 'yellow')

# Start sniffing
log_and_print("Sniffing packets... Press Ctrl+C to stop.", 'white')
try:
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    log_and_print("Sniffing stopped. Output saved to " + output_file, 'red')
    log_file.close()
