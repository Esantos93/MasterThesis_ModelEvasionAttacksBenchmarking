#!/bin/bash

# --- Configuration Paths ---
LOG_DIR="/home/santos/Desktop/Snort_Logs"
BASE_CONFIG="/usr/local/etc/snort/snort.lua"
PLUGIN_PATH="/usr/local/etc/snort/so_rules/"
DAQ_DIR="/usr/local/lib/daq"

# Directories for dynamic selection 
PCAP_DIR="/home/santos/Desktop/Data_Sets/21_To_Snort3"
RULES_DIR="/usr/local/etc/snort/rules"

# --- Create log directory if it doesn't exist ---
mkdir -p "$LOG_DIR"

echo "-------------------------------------------------------"
echo " Snort 3 Dynamic Test Runner"
echo "-------------------------------------------------------"

# --- 1. Dynamic PCAP Selection ---
echo "Step 1: Select the PCAP file to analyze:"
PS3="Enter the number for the PCAP file: "

# Force vertical layout by setting COLUMNS to 1
export COLUMNS=1

select PCAP_PATH in $(find "$PCAP_DIR" -maxdepth 1 -name "*.pcap*" -printf "%f\n"); do
    if [ -n "$PCAP_PATH" ]; then
        FULL_PCAP_PATH="$PCAP_DIR/$PCAP_PATH"
        echo "Selected PCAP: $PCAP_PATH"
        break
    else
        echo "Invalid selection."
    fi
done

echo ""

# --- 2. Dynamic Ruleset Selection ---
echo "Step 2: Select the Ruleset file (.rules):"
echo "0) No Ruleset (Run only built-in inspectors)"

# Get the list of .rules files
RULES_LIST=$(find "$RULES_DIR" -maxdepth 1 -name "*.rules" -printf "%f\n")

PS3="Enter selection (0 for none): "

# select will now display rules one per line due to COLUMNS=1
select RULE_FILE in $RULES_LIST; do
    if [ "$REPLY" == "0" ]; then
        FULL_RULE_PATH=""
        echo "Selected: No external ruleset."
        break
    elif [ -n "$RULE_FILE" ]; then
        FULL_RULE_PATH="$RULES_DIR/$RULE_FILE"
        echo "Selected Ruleset: $RULE_FILE"
        break
    else
        echo "Invalid selection. Please choose a number from the list or 0."
    fi
done

# Reset COLUMNS to default behavior for the rest of the terminal session
unset COLUMNS

# --- 3. Execute Snort ---
echo ""
echo "Running Snort 3..."

# This execution supports the "Comparative Analysis" phase of your thesis
if [ -z "$FULL_RULE_PATH" ]; then
    # Run WITHOUT external rules to check baseline built-in alerts
    sudo snort -c "$BASE_CONFIG" \
               --plugin-path "$PLUGIN_PATH" \
               --daq-dir "$DAQ_DIR" \
               -l "$LOG_DIR" \
               -k none \
               -r "$FULL_PCAP_PATH" \
               --lua "ips = { variables = default_variables, enable_builtin_rules = true }"
else
    # Run WITH the selected ruleset to measure detection accuracy
    sudo snort -c "$BASE_CONFIG" \
               --plugin-path "$PLUGIN_PATH" \
               --daq-dir "$DAQ_DIR" \
               -l "$LOG_DIR" \
               -k none \
               -r "$FULL_PCAP_PATH" \
               --lua "ips = { variables = default_variables, enable_builtin_rules = true, include = '$FULL_RULE_PATH' }"
fi

# --- 4. Permissions ---
# Ensure logs are accessible
sudo chown -R santos:santos "$LOG_DIR"
sudo chmod -R 666 "$LOG_DIR"/*

echo "-------------------------------------------------------"
echo "Test finished. Results available at: $LOG_DIR"