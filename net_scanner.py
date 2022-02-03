#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_args():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target", help="Target IP / IP Range")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify the target ip, for more info use --help :)")
    return options

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broad = broadcast/arp_req
    a_list = scapy.srp(arp_req_broad,timeout=5,verbose=False)[0]
    client_list = []
    for element in a_list:
        client_dict={"ip":element[1].psrc, "mac":element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_res(res_list):
    print("IP\t\t\tMAC\n- - - - - - - - - - - - - - - - - - - - - - -")
    for client in res_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_args()
res=scan(options.target)
print_res(res)

