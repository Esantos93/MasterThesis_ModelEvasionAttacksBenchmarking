import os

# --- Configuration ---
# Terms based on Cisco Talos taxonomy and Edge-IIoTset attack types [cite: 138, 140]
keywords = [
    # --- DDoS / HTTP Flood ---
    #'http_flood', 'http-flood', 'denial-of-service', 'dos-attack', 
    #'slowloris', 'r-u-dead-yet', 'rudy', 'loic', 'hoic', 'syn-flood',
    
    # --- Backdoor & Remote Access ---
    'backdoor', 'shellcode', 'remote-access-terminal', 'reverse-shell',
    'netcat', 'meterpreter', 'rat-tool', 'unauthorized-access',
    
    # --- Ransomware (General and Specific Families) ---
    'ransomware', 'cryptolocker', 'wannacry', 'petya', 'locky', 
    'teslacrypt', 'ryuk', 'maze', 'conti', 'revil', 'darkside',
    
# --- Malware Behavior (C2 and Indicators) ---
# These terms are associated with malware communication patterns and indicators of compromise, which are relevant for both Backdoors and Ransomware attack types.
    'trojan-activity', 'indicator-compromise', 'malware-cnc', 
    'command and control', 'c2-server', 'beaconing', 'callback'
]



input_file = '/home/santos/Desktop/Snort/rules/combined.rules' # Original ruleset from PulledPork [cite: 140]
output_file = '/home/santos/Desktop/Snort/rules/ddos_ransomware_filtered.rules'

def filter_snort_rules():
    total_rules = 0
    filtered_rules = 0

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    with open(input_file, 'r', encoding='utf-8') as f_in, \
         open(output_file, 'w', encoding='utf-8') as f_out:
        
        for line in f_in:
            # Check if line is an active rule (not a comment or empty)
            if line.startswith('alert') or line.startswith('drop') or line.startswith('pass'):
                total_rules += 1
                
                # Search for keywords in the rule definition (case-insensitive)
                line_lower = line.lower()
                if any(key in line_lower for key in keywords):
                    f_out.write(line)
                    filtered_rules += 1
            elif line.strip():
                # Preserve non-rule configuration lines if necessary, 
                # but for this benchmark, we focus on active signatures.
                pass

    print("--------------------------------------------------")
    print(f"Filtering process completed.")
    print(f"Filtered {filtered_rules} rules out of {total_rules} total rules.")
    print(f"Results saved to: {output_file}")
    print("--------------------------------------------------")

if __name__ == "__main__":
    filter_snort_rules()