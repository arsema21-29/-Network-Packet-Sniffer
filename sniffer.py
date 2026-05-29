from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def process_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            print(f"[{timestamp}] TCP | {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}")

        elif UDP in packet:
            print(f"[{timestamp}] UDP | {src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}")

        elif ICMP in packet:
            print(f"[{timestamp}] ICMP | {src_ip} -> {dst_ip}")

def start_sniffer(count=20):
    print("="*55)
    print("        Network Packet Sniffer - Educational Use")
    print("="*55)
    print(f"Capturing {count} packets...\n")
    sniff(prn=process_packet, count=count, store=False)
    print("\nCapture complete.")

if __name__ == "__main__":
    start_sniffer(count=20)
