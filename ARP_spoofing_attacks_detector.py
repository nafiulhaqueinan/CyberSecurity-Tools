#!/usr/bin/env python

import scapy.all as scapy


def get_mac(ip):
    # Function to get the MAC address of a given IP
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None


def sniff(interface):
    # Sniff packets on the given network interface
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    # Process each sniffed packet to detect ARP spoofing
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # ARP reply
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)  # Source IP
            response_mac = packet[scapy.ARP].hwsrc  # MAC from the ARP reply

            if real_mac and real_mac != response_mac:
                print("[+] You are under attack!!")
        except IndexError:
            pass


# Replace "eth0" with the appropriate network interface on your machine
sniff("eth0")
