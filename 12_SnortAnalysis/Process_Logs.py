import os
import subprocess

LOG_DIR = "/home/santos/Desktop/Snort_Logs"

# This function is used to rename the JSON output file with the configuration details
def rename_json(pcap, ruleset, builtin):
    old_file = os.path.join(LOG_DIR, "alert_json.txt")
    new_name = f"json_{pcap}_{ruleset}_{builtin}.json"
    new_file = os.path.join(LOG_DIR, new_name)

    if os.path.exists(old_file):
        # We change the name of the file to include the configuration details
        os.rename(old_file, new_file)

        # Adjust user, group & permissions of the files within the $LOG_DIR
        subprocess.run(["sudo", "chown", "-R", "santos:santos", LOG_DIR], check=True)
        subprocess.run(f"sudo chmod -R 666 {LOG_DIR}/*", shell=True)

        # From JSONL to JSON array format
        fix_json_syntax(new_file)

        print(f"[Process_Logs] File successfully renamed to: {new_name}")
    else:
        print(f"[Process_Logs] Warning: alert_json.txt not found. No alerts generated?")

# This function is used to transform a JSONL file (one JSON object per line) into a proper JSON array format 
def fix_json_syntax(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # We remove blank lines and add commas
    formatted_lines = [line.strip() for line in lines if line.strip()]
    json_array_content = "[\n" + ",\n".join(formatted_lines) + "\n]"
    
    with open(file_path, 'w') as f:
        f.write(json_array_content)