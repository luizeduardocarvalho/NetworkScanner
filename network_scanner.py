#!/usr/bin/env python

import scapy.all as scapy
import argparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\tMAC Address\n-----------------------------------")
    for client in results_list:
        print(client["ip"] + "\t" + client["mac"])


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Gets the IP range that will be scanned.")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify a target IP, use --help for more info.")
    return options.target_ip


target_ip = get_arguments()
scan_result = scan(target_ip)
print_result(scan_result)
