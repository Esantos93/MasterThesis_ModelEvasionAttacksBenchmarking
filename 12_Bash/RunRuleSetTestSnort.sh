#!/bin/bash

# Asegurar que la carpeta existe
mkdir -p /home/santos/Desktop/snort_logs

# Ejecuta Snort
sudo snort -c /usr/local/etc/snort/snort.lua --plugin-path /usr/local/etc/snort/so_rules/ --daq-dir /usr/local/lib/daq -r /home/santos/Desktop/TrafficFiles/test_ping_Mallory.pcap -l /home/santos/Desktop/snort_logs -k none

# Corrige permisos automáticamente al terminar
sudo chown -R santos:santos /home/santos/Desktop/snort_logs
sudo chmod -R 666 /home/santos/Desktop/snort_logs/*
echo "Test finished. Results at ~/Desktop/snort_logs"
