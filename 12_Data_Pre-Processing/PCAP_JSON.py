from scapy.all import rdpcap, wrpcap, IP, TCP, UDP
import json
import binascii

def pcap_to_json(pcap_path):
    packets = rdpcap(pcap_path)
    json_output = []
    
    for i, pkt in enumerate(packets):
        if IP in pkt:
            # Extraemos la info base para el JSON
            pkt_data = {
                "packet_id": i,
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "payload_hex": binascii.hexlify(bytes(pkt[IP].payload)).decode() if pkt[IP].payload else ""
            }
            
            # Si es TCP, añadimos campos específicos de evasión
            if TCP in pkt:
                pkt_data.update({
                    "src_port": pkt[TCP].sport,
                    "dst_port": pkt[TCP].dport,
                    "tcp_flags": int(pkt[TCP].flags),
                    "window": pkt[TCP].window,
                    "options": str(pkt[TCP].options)
                })
            
            json_output.append(pkt_data)
            
    return json.dumps(json_output, indent=4)