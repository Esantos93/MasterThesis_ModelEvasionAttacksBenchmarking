from scapy.all import Ether, IP, TCP, Raw

def json_to_pcap(json_data, output_pcap_path):
    data = json.loads(json_data)
    reconstructed_packets = []
    
    for item in data:
        # Reconstrucción de la capa IP
        # Nota: Los campos como src_ip/dst_ip vienen del LLM (deben ser Read-Only)
        pkt = IP(src=item["src_ip"], dst=item["dst_ip"], proto=item["proto"])
        
        # Añadimos capa de transporte (ejemplo TCP)
        if "src_port" in item:
            pkt = pkt / TCP(
                sport=item["src_port"], 
                dport=item["dst_port"], 
                flags=item["tcp_flags"], 
                window=item["window"]
            )
        
        # Añadimos el Payload modificado por el LLM
        if item["payload_hex"]:
            payload_bytes = binascii.unhexlify(item["payload_hex"])
            pkt = pkt / Raw(load=payload_bytes)
        
        # Generamos el frame de Ethernet base para que el pcap sea válido
        eth_pkt = Ether() / pkt
        reconstructed_packets.append(eth_pkt)
        
    wrpcap(output_pcap_path, reconstructed_packets)
    print(f"Archivo guardado exitosamente en: {output_pcap_path}")