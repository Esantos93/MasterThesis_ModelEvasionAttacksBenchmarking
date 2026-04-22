from scapy.all import rdpcap, wrpcap, IP, TCP, UDP
import json
import binascii

def pcap_to_json(pcap_path):
    packets = rdpcap(pcap_path)
    json_output = []
    
    for i, pkt in enumerate(packets):
        
        # Layer 2 information (Ethernet)
        pkt_data = {
            "packet_id": i + 1,
            "eth_src": pkt.src if hasattr(pkt, 'src') else "00:00:00:00:00:00",
            "eth_dst": pkt.dst if hasattr(pkt, 'dst') else "00:00:00:00:00:00",
            "type": pkt.type if hasattr(pkt, 'type') else None
        }
        
        if IP in pkt:
            # We extract the basic information for the JSON starting from the network layer (layer 3)
            pkt_data.update({
                "packet_id": i-1, # ID - 1 because in Wireshark the first packet is ID 1, but in Python it's index 0
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "payload_hex": binascii.hexlify(bytes(pkt[IP].payload)).decode() if pkt[IP].payload else ""
            })
            
            # If it's TCP, we add specific evasion fields
            if TCP in pkt:
                pkt_data.update({
                    "src_port": pkt[TCP].sport,
                    "dst_port": pkt[TCP].dport,
                    "tcp_flags": int(pkt[TCP].flags),
                    "window": pkt[TCP].window,
                    "options": str(pkt[TCP].options)
                })
        else:
            # If the packet doesn't have an IP layer, we still want to capture its payload (if any) in hex format
            pkt_data["payload_hex"] = binascii.hexlify(bytes(pkt.payload)).decode()
        
        json_output.append(pkt_data)
            
    return json.dumps(json_output, indent=4)