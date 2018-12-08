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
            try:
                    payload = bytes(packet[TCP].payload)
                    url_path = payload[payload.index(b"GET ")+4:payload.index(b" HTTP/1.1")].decode("utf8")
                    http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
                    http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                    url = http_header_parsed["Host"] + url_path + "\n"
                    print(url)
            except:
                pass
    except IndexError:
        pass


sniff(prn=packet_callback, store=0, iface="ens33")
