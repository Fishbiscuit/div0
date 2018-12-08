import os
from scapy.all import *
import time
import subprocess
import signal

def run_bash(bashCommand):
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    process.wait()
    output, error = process.communicate()
    return output

def run_tshark(bashCommand):
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, preexec_fn=os.setsid)
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    return True

def format_packet(packet):
    ret = "***************************************POST PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret

def extract_payload(http_headers, payload, output_path):
    payload_type = http_headers["Content-Type"].split("/")[1].split(";")[0]
    try:
        if "Content-Encoding" in http_headers.keys():
            if http_headers["Content-Encoding"] == "gzip":
                file = zlib.decompress(payload, 16+zlib.MAX_WBITS)
            elif http_headers["Content-Encoding"] == "deflate":
                file = zlib.decompress(payload)
            else:
                file = payload
        else:
            file = payload
    except:
        pass

def stripeverything_pcap(pcap):
    a = rdpcap(pcap)
    sessions = a.sessions()
    #fd = open(output_path, "wb")
    for session in sessions:
        for packet in sessions[session]:
            try:
                """
                #url
                if packet[TCP].dport == 80:
                    payload = bytes(packet[TCP].payload)
                    url_path = payload[payload.index(b"GET ")+4:payload.index(b" HTTP/1.1")].decode("utf8")
                    http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
                    http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                    url = http_header_parsed["Host"] + url_path + "\n"
                    fd.write(url.encode())
                #image
                if packet[TCP].sport == 80:
                    payload = bytes(packet[TCP].payload)
                    http_header_exists = False
                    try:
                        http_header = payload[payload.index(b"HTTP/1.1"):payload.index(b"\r\n\r\n")+2]
                        if http_header:
                            http_header_exists = True
                    except:
                        pass
                    if not http_header_exists and http_payload:
                        http_payload += payload
                    elif http_header_exists and http_payload:
                        http_header_raw = http_payload[:http_payload.index(b"\r\n\r\n")+2]
                        http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                        if "Content-Type" in http_header_parsed.keys():
                            if "image" in http_header_parsed["Content-Type"]:
                                image_payload = http_payload[http_payload.index(b"\r\n\r\n")+4:]
                                if image_payload:
                                    extract_payload(http_header_parsed, image_payload, output_path)
                        http_payload = payload
                    elif http_header_exists and not http_payload:
                        http_payload = payload
                #txt 
                if packet[TCP].sport == 80:
                    payload = bytes(packet[TCP].payload)
                    http_header_exists = False
                    try:
                        http_header = payload[payload.index(b"HTTP/1.1"):payload.index(b"\r\n\r\n")+2]
                        if http_header:
                            http_header_exists = True
                    except:
                        pass
                    if http_header_exists:
                        http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
                        http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                        if "Content-Type" in http_header_parsed.keys():
                            if "text" in http_header_parsed["Content-Type"]:
                                txt_payload = payload[payload.index(b"\r\n\r\n")+4:]
                                if txt_payload:
                                    extract_payload(http_header_parsed, txt_payload, output_pathemail
                if packet[TCP].payload:
                    mail_packet = str(packet[TCP].payload)
                    if 'user' in mail_packet.lower() or 'pass' in mail_packet.lower():
                        print ('[*] Server: %s' % packet[IP].dst)
                        print ('[*] %s' %packet[TCP].payload)
            """
            #POST
                http_packet = str(packet)
                if http_packet.find('POST'):
                    print(format_packet(http_packet))
                    
            except:
                pass

while True:
    pcap_name = str(time.time())+".pcap"

    print("pcap_name:", pcap_name)

    print("Starting capture...")

    run_bash("touch "+pcap_name)
    run_bash("chmod 777 "+pcap_name)
    run_tshark("tshark -i ens33 -w "+ pcap_name)

    print("Ended capture...")

    run_bash("tshark -r " +pcap_name+  " --export-object http,./output/")

    #run_bash("ls output")

    stripeverything_pcap(pcap_name)

    



