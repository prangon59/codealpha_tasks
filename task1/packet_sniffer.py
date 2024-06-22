import socket
from scapy.all import sniff, Ether, IP, TCP, UDP
import psutil
import datetime
import json

# Function to get the Wi-Fi interface
def get_wifi_interface():
    interfaces = psutil.net_if_addrs()
    for interface, snics in interfaces.items():
        if 'Wi-Fi' in interface or 'WLAN' in interface:
            for snic in snics:
                if snic.family == socket.AF_INET:
                    return interface
    return None

# Packet processing function
def process_packet(packet):
    try:
        with open("packets.json", "a") as f:
            timestamp = str(datetime.datetime.now())
            packet_info = {"timestamp": timestamp}
            
            if Ether in packet:
                eth = packet[Ether]
                packet_info["ethernet"] = {
                    "destination_mac": eth.dst,
                    "source_mac": eth.src,
                    "type": eth.type
                }

                if IP in packet:
                    ip = packet[IP]
                    packet_info["ipv4"] = {
                        "version": ip.version,
                        "header_length": ip.ihl,
                        "ttl": ip.ttl,
                        "protocol": ip.proto,
                        "source_ip": ip.src,
                        "destination_ip": ip.dst
                    }

                    if ip.proto == 6 and TCP in packet:
                        tcp = packet[TCP]
                        packet_info["tcp"] = {
                            "source_port": tcp.sport,
                            "destination_port": tcp.dport,
                            "sequence_number": tcp.seq,
                            "acknowledgment_number": tcp.ack,
                            "flags": {
                                "FIN": tcp.flags.F,
                                "SYN": tcp.flags.S,
                                "RST": tcp.flags.R,
                                "PSH": tcp.flags.P,
                                "ACK": tcp.flags.A,
                                "URG": tcp.flags.U
                            }
                        }

                    elif ip.proto == 17 and UDP in packet:
                        udp = packet[UDP]
                        packet_info["udp"] = {
                            "source_port": udp.sport,
                            "destination_port": udp.dport,
                            "length": udp.len
                        }

            # Write packet info to JSON file
            f.write(json.dumps(packet_info) + "\n")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Main function to start sniffing
def main():
    interface = get_wifi_interface()
    
    if not interface:
        print("Error: Wi-Fi interface not found.")
        return
    
    print(f"Wi-Fi interface found: {interface}")
    
    # Sniff packets on the Wi-Fi interface and apply process_packet function to each captured packet
    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("Sniffing stopped.")

if __name__ == "__main__":
    main()
