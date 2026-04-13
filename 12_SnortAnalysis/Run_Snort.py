import os
import subprocess

# --- Configuration Paths ---
LOG_DIR = "/home/santos/Desktop/Snort_Logs"
BASE_CONFIG = "/usr/local/etc/snort/snort.lua"
PLUGIN_PATH = "/usr/local/etc/snort/so_rules/"
DAQ_DIR = "/usr/local/lib/daq"

# Directories for dynamic selection
PCAP_DIR = "/home/santos/Desktop/Traffic_Files"
RULES_DIR = "/usr/local/etc/snort/rules"

def get_selection(file_list, prompt):
    """ Helper to create a numbered menu for the user """
    print(f"\n{prompt}")
    for i, file in enumerate(file_list, 1):
        print(f"{i}) {file}")
    
    while True:
        try:
            choice = int(input("Enter number selection: "))
            if 1 <= choice <= len(file_list):
                return file_list[choice-1]
        except ValueError:
            pass
        print("Invalid selection. Try again.")

def execute_snort():
#def main():
    # 1. Ensure log directory exists
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    # 2. Select PCAP
    pcaps = sorted([f for f in os.listdir(PCAP_DIR) if f.endswith(('.pcap', '.pcapng'))])
    selected_pcap = get_selection(pcaps, "Step 1: Select the PCAP file to analyze:")
    full_pcap_path = os.path.join(PCAP_DIR, selected_pcap)

    # 3. Select Ruleset
    rules = sorted([f for f in os.listdir(RULES_DIR) if f.endswith('.rules')])
    # Add option 0 manually
    print("\nStep 2: Select the Ruleset file:\n0) No Ruleset (Run only built-in inspectors)")
    for i, rule in enumerate(rules, 1): print(f"{i}) {rule}")
    rule_choice = input("Enter selection (0 for none): ")
    
    rule_name = "noRuleset"
    full_rule_path = ""
    if rule_choice != '0':
        rule_name = rules[int(rule_choice)-1]
        full_rule_path = os.path.join(RULES_DIR, rules[int(rule_choice)-1])

    # 4. Built-in Rules Toggle (Your new requirement)
    print("\nStep 3: Protocol Inspectors (Built-in Rules)")
    print("1) Enabled (Detect anomaly noise - GID 116, 135, etc.)")
    print("2) Disabled (Pure Signature testing - GID 1 ONLY)")
    bi_choice = input("Select option: ")
    bi_status = "true" if bi_choice == "1" else "false"
    bi_label = "B" if bi_choice == "1" else "nB"

    # 5. Build the LUA string for the Snort command
    # This is where we inject our dynamic choices
    lua_ips_config = f"ips = {{ variables = default_variables, enable_builtin_rules = {bi_status}"
    if full_rule_path: lua_ips_config += f", include = '{full_rule_path}'"
    lua_ips_config += " }"

    # 6. Construct the final shell command
    # Using 'sudo' because Snort often needs it for DAQ or restricted paths
    snort_cmd = [
        "sudo", "snort",
        "-c", BASE_CONFIG,
        "--plugin-path", PLUGIN_PATH,
        "--daq-dir", DAQ_DIR,
        "-l", LOG_DIR,
        "-k", "none",
        "-r", full_pcap_path,
        "--lua", lua_ips_config
    ]

    print(f"\nExecuting: {' '.join(snort_cmd)}\n")
    
    # 7. Execute Snort
    try:
        # subprocess.run waits for snort to finish
        subprocess.run(snort_cmd, check=True)

        # 8. Set ownership and permissions for the output files
        # subprocess.run(["sudo", "chown", "-R", "santos:santos", LOG_DIR])
        # subprocess.run(f"sudo chmod -R 666 {LOG_DIR}/*", shell=True)
        
        # print("\n" + "-"*55)
        # print(f"Test finished. Results available at {LOG_DIR}")
        # print("-"*55)

    except subprocess.CalledProcessError as e:
        print(f"Error executing Snort: {e}")

    #8. Return the selections for potential use in other parts of the program

    return {
        "pcap": selected_pcap.split('.')[0],
        "ruleset": rule_name.replace(".rules", ""),
        "builtin": bi_label
    }

# if __name__ == "__main__":
#    main()