#!/bin/bash

# --- Configuration Paths ---
LOG_DIR="/home/santos/Desktop/Snort_Logs"
PCAP_PATH="/home/santos/Desktop/Traffic_Files/test_ping_Mallory.pcap"
# To be used if we want to loop through multiple pcap files in a directory instead of a single file
PCAP_DIR=""
PCAP_FILTER="*.pcap"
CONFIG_FILE="/usr/local/etc/snort/snort.lua"
PLUGIN_PATH="/usr/local/etc/snort/so_rules/"
DAQ_DIR="/usr/local/lib/daq"

# --- Create log directory if it doesn't exist ---
mkdir -p "$LOG_DIR"

# --- Execute Snort with defined variables ---
# Using backslashes to break the command into multiple lines for better readability
sudo snort -c "$CONFIG_FILE" \
        --lua "ips.include = '/home/santos/Desktop/Local_Rules_Copy.rules'"\
        --plugin-path "$PLUGIN_PATH" \
        --daq-dir "$DAQ_DIR" \
        -r "$PCAP_PATH" \
        #--pcap-dir "$PCAP_DIR" \
        #--pcap-filter "$PCAP_FILTER" \
        -l "$LOG_DIR" \
        -k none

# Change ownership and permissions of the log files to ensure they are accessible
sudo chown -R santos:santos /home/santos/Desktop/Snort_Logs
sudo chmod -R 666 /home/santos/Desktop/Snort_Logs/*
echo "Test finished. Results at ~/Desktop/Snort_Logs"
