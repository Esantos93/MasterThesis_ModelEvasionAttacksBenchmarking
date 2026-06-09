from scapy.all import Ether, IP, TCP, Raw, wrpcap
import json
import binascii

def json_to_pcap(json_data, output_pcap_path):
    data = json.loads(json_data)
    reconstructed_packets = []
    
    for item in data:
        # 1. Final assembly of Layer 2 (Ethernet) with the new fields
        # We use .get() to avoid errors if the key doesn't exist
        eth_pkt = Ether(
            src=item.get("eth_src", "00:00:00:00:00:00"), 
            dst=item.get("eth_dst", "00:00:00:00:00:00"),
            type=item.get("type", 0x800)
        )
        
        pkt = None
        
        # 2. Final assembly of Layer 3 (IP) - Only if src_ip exists
        if "src_ip" in item:
            pkt = IP(src=item["src_ip"], dst=item["dst_ip"], proto=item["proto"])
            
            # 3. Layer 4 (TCP)
            if "src_port" in item:
                pkt = pkt / TCP(
                    sport=item["src_port"], 
                    dport=item["dst_port"], 
                    flags=item["tcp_flags"], 
                    window=item.get("window", 8192)
                )
        
        # 4. Payload (Either IP or not)
        payload = b""
        if item.get("payload_hex"):
            payload = binascii.unhexlify(item["payload_hex"])
        
        # Final assembly of the packet
        if pkt:
            final_packet = eth_pkt / pkt / Raw(load=payload)
        else:
            final_packet = eth_pkt / Raw(load=payload)
            
        reconstructed_packets.append(final_packet)
        
    wrpcap(output_pcap_path, reconstructed_packets)
    print(f"File saved to: {output_pcap_path}")