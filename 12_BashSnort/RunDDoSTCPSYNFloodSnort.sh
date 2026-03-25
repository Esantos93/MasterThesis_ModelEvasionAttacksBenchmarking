#!/bin/bash

# --- Configuration Paths ---
LOG_DIR="/home/santos/Desktop/Snort_Logs"
PCAP_PATH="/home/santos/Desktop/Traffic_Files/Edge-IIoTset_dataset/Attack_traffic/DDoS_TCP_SYN_Flood_Attacks.pcap"
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
           --plugin-path "$PLUGIN_PATH" \
           --daq-dir "$DAQ_DIR" \
           -l "$LOG_DIR" \
           -k none \
           -r "$PCAP_PATH" \
           #--pcap-dir "$PCAP_DIR" \
           #--pcap-filter "$PCAP_FILTER" \

# --- Set ownership and permissions for the output files ---
sudo chown -R santos:santos "$LOG_DIR"
sudo chmod -R 666 "$LOG_DIR"/*


echo "Test finished. Results are available at $LOG_DIR"