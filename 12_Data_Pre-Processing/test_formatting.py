import os, json
from PCAP_JSON import pcap_to_json
from JSON_PCAP import json_to_pcap

def main():
    
    # Path configuration
    pcap_path = "/home/santos/Desktop/Data_Sets/10_Own_Traffic/test_ping_Mallory.pcap"
    base_path, _ = os.path.splitext(pcap_path)
    json_path = base_path + ".json"
    pcap_reconstructed = base_path + "_reconstructed.pcap"

    # STEP 1: Convert PCAP to JSON
    print("--- Converting PCAP to JSON ---")
    json_result = pcap_to_json(pcap_path)
    #print(json_result)

    try:
            with open(json_path, 'w', encoding='utf-8') as f:
                f.write(json_result)
            
            print(f"Success: File saved to {json_path}")
    except Exception as e:
            print(f"Error while writing the file: {e}")

    # STEP 2: Convert JSON back to PCAP
    print("\n--- Converting JSON back to PCAP ---")
    try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data_from_file = f.read()
            
            # Procesamos los datos
            json_to_pcap(data_from_file, pcap_reconstructed)
            print(f"PCAP reconstruction successful. File saved to: {pcap_reconstructed}")

    except FileNotFoundError:
            print(f"Error: The file '{json_path}' does not exist.")
    except PermissionError:
            print(f"Error: You do not have permissions to read the file.")
    except json.JSONDecodeError:
            print(f"Error: The file exists but the JSON format is invalid.")
    except Exception as e:
            print(f"Unexpected error occurred: {e}")

if __name__ == "__main__":
    main()