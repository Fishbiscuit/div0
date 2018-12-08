import os
from scapy.all import *
import time
import subprocess

def run_bash(bashCommand):
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    process.wait()
    output, error = process.communicate()
    return output

def run_export_objects():
    process = subprocess.Popen(["sudo", "tshark", "-r", pcap_name, "--export-object", 'http,./output/'], stdout=subprocess.PIPE)
    process.wait()
    output, error = process.communicate()
    return output

while True:
    pcap_name = str(time.time())+".pcap"

    print("pcap_name:", pcap_name)

    print("Starting capture...")

    run_bash("touch "+pcap_name)
    run_bash("chmod 777 "+pcap_name)
    run_bash("sudo tshark -i ens33 -w "+ pcap_name + " -c 500")

    print("Ended capture...")

    run_bash("sudo tshark -r " +pcap_name+  " --export-object http,./output/")

    run_bash("ls output")

    



