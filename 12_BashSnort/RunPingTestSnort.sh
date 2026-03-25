#!/bin/bash

# We check if the log directory exists, if not we create it
mkdir -p /home/santos/Desktop/Snort_Logs

# Execute Snort with the specified configuration, plugin path, and DAQ directory, reading from the specified pcap file and logging to the specified directory
sudo snort -c /usr/local/etc/snort/snort.lua --lua "ips.include = '/home/santos/Desktop/local_off.rules'" --daq-dir /usr/local/lib/daq -r /home/santos/Desktop/Traffic_Files/test_ping_Mallory.pcap -l /home/santos/Desktop/Snort_Logs -k none

# Change ownership and permissions of the log files to ensure they are accessible
sudo chown -R santos:santos /home/santos/Desktop/Snort_Logs
sudo chmod -R 666 /home/santos/Desktop/Snort_Logs/*
echo "Test finished. Results at ~/Desktop/Snort_Logs"
