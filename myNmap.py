#!/usr/bin/env python3

from socket import timeout
import sys
from scapy.all import *

global dst_ip
global portnum

timeout = 0.2

if len(sys.argv) > 4 or len(sys.argv) < 3:
    print("Usage: python3 nmap.py SCAN IP [PORT]")
    print("Scan Types: SYN, SYNACK, XMAS, NULL")
    exit(1)

portnum = None

if len(sys.argv) == 4 and sys.argv[3].isnumeric():
    portnum = int(sys.argv[3])
    if portnum < 0 or portnum > 65535:
        print("Please provide a valid port number: 0-65,535")
        exit(1)
    
dst_ip = str(sys.argv[2])

#SYN Scan
def synScan(p):
    stealth_scan = sr1(IP(dst=dst_ip)/TCP(dport=p, flags="S"),timeout=timeout, verbose=0)

    if stealth_scan != None:
        if stealth_scan.haslayer(TCP):
            if str(stealth_scan.getlayer(TCP).flags) == "RA":
                print(str(p) + ": Closed\n")
            elif str(stealth_scan.getlayer(TCP).flags) == "SA":
                print(str(p) + ": Open\n")
                send_rst = sr(IP(dst=dst_ip)/TCP(dport=p, flags="R"), timeout=timeout, verbose=0)

#SYNACK Scan
def synAckScan(p):
    full_connect = sr1(IP(dst=dst_ip)/TCP(dport=p, flags="S"),timeout=timeout, verbose=0)

    if full_connect != None:
        if full_connect.haslayer(TCP):
            if str(full_connect.getlayer(TCP).flags) == "RA":
                print(str(p) + ": Closed\n")
            elif str(full_connect.getlayer(TCP).flags) == "SA":
                print(str(p) + ": Open\n")
                send_ack = sr(IP(dst=dst_ip)/TCP(dport=p, flags="A"), timeout=timeout, verbose=0) # full-connect instead of RST

#XMAS Scan
def xmasScan(p):
    xmas = sr1(IP(dst=dst_ip)/TCP(dport=p, flags="FPU"), timeout=timeout, verbose=0)

    if xmas == None:
        print(str(p) + ": Open\n")

    elif xmas != None and xmas.haslayer(TCP):
        if str(xmas.getlayer(TCP).flags) == "RA":
            print(str(p) + ": Closed\n")

#NULL Scan
def nullScan(p):
    null = sr1(IP(dst=dst_ip)/TCP(dport=p, flags=""), timeout=timeout, verbose=0)

    if null == None:
        print(str(p) + ": Open\n")

    elif null.haslayer(TCP):
        if str(null.getlayer(TCP).flags) == "RA":
            print(str(p) + ": Closed\n")


if sys.argv[1] == "SYN" or sys.argv[1] == "syn":
    if portnum == None:
        for p in range(1, 10001):
           synScan(p)
    else:
        synScan(portnum)

if sys.argv[1] == "SYNACK" or sys.argv[1] == "synack":
    if portnum == None:
        for p in range(1, 10001):
           synAckScan(p)
    else:
        synAckScan(portnum)

if sys.argv[1] == "XMAS" or sys.argv[1] == "xmas":
    if portnum == None:
        for p in range(1, 10001):
           xmasScan(p)
    else:
        xmasScan(portnum)

if sys.argv[1] == "NULL" or sys.argv[1] == "null":
    if portnum == None:
        for p in range(1, 10001):
           nullScan(p)
    else:
        nullScan(portnum)

print("Scan Complete")
exit(0)