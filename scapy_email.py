from scapy.all import *

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
        print(file)
    except:
        pass

def packet_callback(packet):
    try:
        # check to make sure it has a data payload
        if packet[TCP].payload:
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
                            extract_payload(http_header_parsed, txt_payload, "./output")

            if packet[TCP].dport == 80:
                    payload = bytes(packet[TCP].payload)
                    url_path = payload[payload.index(b"GET ")+4:payload.index(b" HTTP/1.1")].decode("utf8")
                    http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
                    http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                    url = http_header_parsed["Host"] + url_path + "\n"
                    print(url)
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
    except IndexError:
        pass


sniff(prn=packet_callback, store=0, iface="ens33")
